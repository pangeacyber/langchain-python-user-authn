from __future__ import annotations

import logging
import sys
import threading
import urllib
import webbrowser
from functools import partial
from pathlib import Path
from queue import Queue
from secrets import token_hex
from typing import Any, override

import click
from dotenv import load_dotenv
from flask import Flask, abort, request
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_community.document_loaders import DirectoryLoader
from langchain_community.vectorstores import FAISS
from langchain_core.prompts.chat import ChatPromptTemplate
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter
from pangea import PangeaConfig
from pangea.services import AuthN
from pydantic import SecretStr

from langchain_user_authn.retrievers import AuthzRetriever

load_dotenv(override=True)

PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "human",
            """You are an assistant for question-answering tasks. Use the following pieces of retrieved context to answer the question. If you don't know the answer, just say that you don't know and that the user may not be authorized to know the answer. Use three sentences maximum and keep the answer concise.
Question: {input}
Context: {context}
Answer:""",
        ),
    ]
)

docs_loader = DirectoryLoader(
    str(Path(__file__).parent.joinpath("data").resolve(strict=True)), glob="**/*.md", show_progress=True
)
docs = docs_loader.load()

# Add category metadata based on parent directory.
for doc in docs:
    source = doc.metadata.get("source", None)
    assert source
    doc.metadata["category"] = Path(source).parent.name

docs_split = CharacterTextSplitter().split_documents(docs)


class SecretStrParamType(click.ParamType):
    name = "secret"

    @override
    def convert(self, value: Any, param: click.Parameter | None = None, ctx: click.Context | None = None) -> SecretStr:
        if isinstance(value, SecretStr):
            return value

        return SecretStr(value)


SECRET_STR = SecretStrParamType()


@click.command()
@click.option(
    "--authn-client-token",
    envvar="PANGEA_AUTHN_CLIENT_TOKEN",
    type=str,
    required=True,
    help="Pangea AuthN Client API token. May also be set via the `PANGEA_AUTHN_CLIENT_TOKEN` environment variable.",
)
@click.option(
    "--authn-hosted-login",
    envvar="PANGEA_AUTHN_HOSTED_LOGIN",
    type=str,
    required=True,
    help="Pangea AuthN Hosted Login URL. May also be set via the `PANGEA_AUTHN_HOSTED_LOGIN` environment variable.",
)
@click.option(
    "--authz-token",
    envvar="PANGEA_AUTHZ_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea AuthZ API token. May also be set via the `PANGEA_AUTHZ_TOKEN` environment variable.",
)
@click.option(
    "--pangea-domain",
    envvar="PANGEA_DOMAIN",
    default="aws.us.pangea.cloud",
    show_default=True,
    required=True,
    help="Pangea API domain. May also be set via the `PANGEA_DOMAIN` environment variable.",
)
@click.option("--model", default="gpt-4o-mini", show_default=True, required=True, help="OpenAI model.")
@click.option(
    "--openai-api-key",
    envvar="OPENAI_API_KEY",
    type=SECRET_STR,
    required=True,
    help="OpenAI API key. May also be set via the `OPENAI_API_KEY` environment variable.",
)
@click.argument("prompt")
def main(
    *,
    prompt: str,
    authn_client_token: str,
    authn_hosted_login: str,
    authz_token: SecretStr,
    pangea_domain: str,
    model: str,
    openai_api_key: SecretStr,
) -> None:
    authn = AuthN(token=authn_client_token, config=PangeaConfig(domain=pangea_domain))

    # This queue will be used to pass data between the CLI and server threads.
    queue: Queue[str] = Queue()

    # Web server to handle the authentication flow callback.
    app = Flask(__name__)
    app.logger.disabled = True
    logger = logging.getLogger("werkzeug")
    logger.setLevel(logging.ERROR)
    logger.disabled = True
    sys.modules["flask.cli"].show_server_banner = lambda *x: None  # type: ignore[attr-defined]

    state = token_hex(32)

    @app.route("/callback")
    def callback():
        # Verify that the state param matches the original.
        if request.args.get("state") != state:
            return abort(401)

        auth_code = request.args.get("code")
        if auth_code is None:
            return abort(401)

        # Exchange the authorization code for the user's tokens and info.
        response = authn.client.userinfo(code=auth_code)
        if not response.success or response.result is None or response.result.active_token is None:
            return abort(401)

        queue.put(response.result.active_token.token)
        queue.task_done()

        return "Done, you can close this tab."

    # Spawn the server thread.
    func = partial(app.run, port=3000, debug=False)
    app_thread = threading.Thread(target=func, daemon=True)
    app_thread.start()

    # Open a new browser tab to authenticate.
    url_parameters = {"redirect_uri": "http://localhost:3000/callback", "response_type": "code", "state": state}
    url = f"{authn_hosted_login}?{urllib.parse.urlencode(url_parameters)}"
    click.echo("Opening browser to authenticate...")
    click.echo(f"URL: <{url}>")
    webbrowser.open_new_tab(url)

    # Wait for the server to receive the auth code.
    token = queue.get(block=True)
    check_result = authn.client.token_endpoints.check(token).result
    assert check_result
    owner = check_result.owner
    click.echo(f"Authenticated as {owner}.")
    click.echo()

    # Set up vector store
    embeddings_model = OpenAIEmbeddings(api_key=openai_api_key)
    vectorstore = FAISS.from_documents(documents=docs_split, embedding=embeddings_model)

    # Set up a retriever that will filter documents based on the user's
    # permissions in AuthZ.
    retriever = AuthzRetriever(
        vectorstore=vectorstore, username=check_result.owner, token=authz_token, domain=pangea_domain
    )

    # Create the chain.
    llm = ChatOpenAI(model=model, api_key=openai_api_key)
    qa_chain = create_stuff_documents_chain(llm, PROMPT)
    rag_chain = create_retrieval_chain(retriever, qa_chain)

    click.echo(rag_chain.invoke({"input": prompt})["answer"])


if __name__ == "__main__":
    main()
