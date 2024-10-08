# langchain-python-user-authn

An example CLI tool in Python demonstrating how to integrate Pangea's [AuthN][]
and [AuthZ][] services into a LangChain app to filter out RAG documents based on
user permissions.

## Prerequisites

- Python v3.12 or greater.
- pip v24.2 or [uv][] v0.4.18.
- A [Pangea account][Pangea signup] with AuthN and AuthZ enabled.
- An [OpenAI API key][OpenAI API keys].
- libmagic
  - macOS: `brew install libmagic`
  - Windows: included via the python-magic-bin package

The setup in AuthN should include `http://localhost:3000` as a redirect
(callback) URL.

The setup in AuthZ should look something like this:

### Resource types

| Name        | Permissions |
| ----------- | ----------- |
| engineering | read        |
| finance     | read        |

### Roles & access

> [!TIP]
> At this point you need to create 2 new Roles under the `Roles & Access` tab in the Pangea console named `engineering` and `finance`.

#### Role: engineering

| Resource type | Permissions (read) |
| ------------- | ------------------ |
| engineering   | ✔️                 |
| finance       | ❌                 |

#### Role: finance

| Resource type | Permissions (read) |
| ------------- | ------------------ |
| engineering   | ❌                 |
| finance       | ✔️                 |

### Assigned roles & relations

| Subject type | Subject ID        | Role/Relation |
| ------------ | ----------------- | ------------- |
| user         | alice@example.org | engineering   |
| user         | bob@example.org   | finance       |

## Setup

```shell
git clone https://github.com/pangeacyber/langchain-python-user-authn.git
cd langchain-python-user-authn
```

If using pip:

```shell
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or, if using uv:

```shell
uv sync
source .venv/bin/activate
```

The sample can then be executed with:

```shell
python -m langchain_user_authn
```

## Usage

```
Usage: python -m langchain_user_authn [OPTIONS] PROMPT

Options:
  --authn-client-token TEXT  Pangea AuthN Client API token. May also be set
                             via the `PANGEA_AUTHN_CLIENT_TOKEN` environment
                             variable.  [required]
  --authn-hosted-login TEXT  Pangea AuthN Hosted Login URL. May also be set
                             via the `PANGEA_AUTHN_HOSTED_LOGIN` environment
                             variable.  [required]
  --authz-token SECRET       Pangea AuthZ API token. May also be set via the
                             `PANGEA_AUTHZ_TOKEN` environment variable.
                             [required]
  --pangea-domain TEXT       Pangea API domain. May also be set via the
                             `PANGEA_DOMAIN` environment variable.  [default:
                             aws.us.pangea.cloud; required]
  --model TEXT               OpenAI model.  [default: gpt-4o-mini; required]
  --openai-api-key SECRET    OpenAI API key. May also be set via the
                             `OPENAI_API_KEY` environment variable.
                             [required]
  --help                     Show this message and exit.
```

Let's assume the current user is "alice@example.org" and that they should have
permission to see engineering documents. They can query the LLM on information
regarding those documents:

```
$ python -m langchain_user_authn "What is the software architecture of the company?"
```

This will open a new tab in the user's default web browser where they can login
through AuthN. Afterwards, their permissions are checked against AuthZ and they
will indeed receive a response that is derived from the engineering documents:

```
The company's software architecture consists of a frontend built with ReactJS,
Redux, and Axios, along with Material-UI for design components. The backend
utilizes Node.js and Express.js, with MongoDB as the database. Authentication
and authorization are managed through JSON Web Tokens (JWT) and OAuth 2.0, and
version control is handled using Git and GitHub.
```

But they cannot query finance information:

```
$ python -m langchain_user_authn "What is the top salary in the Engineering department?"

[login flow]

I don't know the answer to that question, and you may not be authorized to know the answer.
```

And vice versa for "bob@example.org", who is in finance but not engineering.

[AuthN]: https://pangea.cloud/docs/authn/
[AuthZ]: https://pangea.cloud/docs/authz/
[Pangea signup]: https://pangea.cloud/signup
[OpenAI API keys]: https://platform.openai.com/api-keys
[uv]: https://docs.astral.sh/uv/
