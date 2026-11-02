"""Package-name analysis that needs no network: lookalikes of popular packages and import-name mix-ups."""

from __future__ import annotations

import re

# Well-known packages. A dependency on one of these is never a lookalike and never needs a registry lookup.
# Hand-curated, not exhaustive: the list only has to cover the names worth impersonating.
POPULAR = {
    "pypi": set("""
        boto3 botocore urllib3 requests setuptools certifi charset-normalizer idna typing-extensions python-dateutil
        s3transfer packaging six numpy pyyaml fsspec s3fs pip cryptography google-api-core pydantic pydantic-core cffi
        attrs pycparser pandas importlib-metadata jmespath protobuf rsa pyasn1 pyasn1-modules click zipp platformdirs
        markupsafe jinja2 wheel pytz filelock colorama awscli pyjwt tomli pluggy pytest virtualenv cachetools
        googleapis-common-protos google-auth jsonschema sqlalchemy wrapt pyarrow psutil docutils aiohttp
        requests-oauthlib oauthlib iniconfig exceptiongroup yarl multidict frozenlist aiosignal pyparsing tomlkit
        soupsieve beautifulsoup4 decorator scipy greenlet pillow openpyxl isodate lxml async-timeout h11 httpx httpcore
        anyio sniffio werkzeug flask itsdangerous gunicorn uvicorn fastapi starlette django djangorestframework celery
        redis kombu psycopg2 psycopg2-binary psycopg pymysql mysql-connector-python pymongo matplotlib seaborn
        scikit-learn scikit-image tensorflow torch torchvision torchaudio transformers tokenizers huggingface-hub
        datasets openai anthropic langchain langchain-core langchain-community langchain-openai tiktoken tqdm rich typer
        black isort flake8 pylint mypy ruff pre-commit coverage pytest-cov pytest-asyncio pytest-mock tox sphinx
        selenium playwright scrapy paramiko pexpect tabulate python-dotenv pyopenssl websocket-client websockets grpcio
        grpcio-status regex nltk spacy opencv-python opencv-python-headless networkx sympy xlrd xlsxwriter markdown
        mistune pygments prompt-toolkit ipython jupyter notebook ipykernel nbformat tornado pyzmq simplejson ujson
        orjson msgpack marshmallow alembic sqlmodel email-validator bcrypt passlib python-multipart python-jose authlib
        stripe twilio sendgrid slack-sdk discord-py python-telegram-bot pyserial pywin32 pyinstaller docker kubernetes
        ansible fabric invoke toml jsonpointer arrow pendulum faker factory-boy hypothesis mock responses freezegun
        sentry-sdk loguru structlog prometheus-client streamlit gradio dash plotly bokeh xgboost lightgbm catboost
        statsmodels keras jax onnx onnxruntime sentence-transformers accelerate peft bitsandbytes llama-index chromadb
        pinecone qdrant-client faiss-cpu ollama google-generativeai google-genai cohere mistralai yt-dlp pytube moviepy
        pydub pyautogui pynput pygame kivy pyqt5 pyqt6 pyside6 shapely geopandas folium pycryptodome pycryptodomex
        pynacl scapy impacket pwntools yara-python pefile capstone requests-toolbelt pysocks httplib2 uritemplate
        google-cloud-storage google-cloud-bigquery azure-core azure-storage-blob azure-identity msal python-docx
        python-pptx pymupdf pypdf pdfplumber reportlab qrcode python-magic tenacity backoff pyperclip schedule apscheduler
        humanize python-slugify unidecode emoji deepdiff jsonpatch pyotp boto ruamel-yaml dataclasses-json
        attrs cattrs more-itertools toolz cython numba polars duckdb dask joblib threadpoolctl pympler setuptools-scm
        hatchling poetry poetry-core pdm uv twine build flit-core nox httpx-sse sse-starlette aiofiles watchdog
    """.split()),
    "npm": set("""
        lodash react react-dom express axios chalk commander debug tslib typescript moment dayjs uuid classnames
        prop-types semver glob minimist yargs fs-extra rimraf mkdirp dotenv cors body-parser cookie-parser
        jsonwebtoken bcrypt bcryptjs mongoose mongodb mysql mysql2 pg sequelize prisma redis ioredis socket.io
        socket.io-client ws next vue nuxt svelte vite webpack webpack-cli babel-loader rollup esbuild eslint prettier
        jest mocha chai vitest supertest nodemon ts-node tsx zod yup joi ajv ramda rxjs redux react-redux zustand
        react-router react-router-dom styled-components tailwindcss postcss autoprefixer sass less jquery underscore
        bluebird async request node-fetch got superagent cheerio puppeteer playwright jsdom marked markdown-it
        highlight.js chart.js d3 three qs query-string path-to-regexp cross-env concurrently inquirer ora boxen
        figlet colors kleur picocolors nanoid crypto-js node-forge helmet morgan winston pino multer sharp jimp
        nodemailer stripe openai firebase firebase-admin aws-sdk passport passport-jwt express-session graphql
        apollo-server knex typeorm class-validator class-transformer reflect-metadata date-fns luxon immer swr
        formik react-hook-form framer-motion gsap electron electron-builder react-native expo xml2js js-yaml yaml ini
        toml csv-parse papaparse xlsx pdfkit jspdf sqlite3 better-sqlite3 mime mime-types http-proxy
        http-proxy-middleware compression serve-static serve gulp grunt karma cypress husky lint-staged nx lerna
        turbo lru-cache ms ansi-regex strip-ansi supports-color color-convert escape-string-regexp inherits
        safe-buffer readable-stream once graceful-fs minimatch signal-exit which cross-spawn execa p-limit preact
        lit solid-js astro remix angular hono fastify koa nestjs sanitize-html dompurify validator express-validator
        express-rate-limit http-errors cookie jose uuidv4 shelljs zx open chokidar dotenv-expand
    """.split()),
}

# Import names that are not the package name. Asking for the import name is a classic AI slip:
# the name on the registry is someone else's project, a dead placeholder, or free for anyone to register.
IMPORT_NAME_MIXUPS = {
    "sklearn": "scikit-learn",
    "cv2": "opencv-python",
    "yaml": "pyyaml",
    "pil": "pillow",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "crypto": "pycryptodome",
    "dateutil": "python-dateutil",
    "magic": "python-magic",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "telegram": "python-telegram-bot",
    "serial": "pyserial",
    "usb": "pyusb",
    "attr": "attrs",
    "fitz": "pymupdf",
    "skimage": "scikit-image",
    "win32api": "pywin32",
    "zmq": "pyzmq",
    "openssl": "pyopenssl",
    "websocket": "websocket-client",
    "jose": "python-jose",
    "multipart": "python-multipart",
    "faiss": "faiss-cpu",
}

MIN_LOOKALIKE_LENGTH = 5  # shorter names collide with each other far too often to be meaningful


def canonical(name: str, ecosystem: str) -> str:
    """PEP 503 normalisation for PyPI; npm names are already case-sensitive-lowercase."""
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name.lower()


def is_popular(name: str, ecosystem: str) -> bool:
    return canonical(name, ecosystem) in POPULAR[ecosystem]


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment): a swap of two neighbours costs 1, like a typo does."""
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


_PREFIXES = ("python-", "py-", "node-")
_SUFFIXES = ("-python", "-py", "-js", "-node", "-lib", "-sdk", "-api", "-dev")


def _without_affixes(n: str):
    for prefix in _PREFIXES:
        if n.startswith(prefix):
            yield n[len(prefix):]
    for suffix in _SUFFIXES:
        if n.endswith(suffix):
            yield n[:-len(suffix)]


def lookalike(name: str, ecosystem: str) -> str | None:
    """The popular package this name imitates (one typo away, or the same name with a decorative affix)."""
    n = canonical(name, ecosystem)
    popular = POPULAR[ecosystem]
    if n in popular or n.startswith("@"):
        return None
    for bare in _without_affixes(n):
        if len(bare) >= 4 and bare in popular:
            return bare
    if len(n) < MIN_LOOKALIKE_LENGTH:
        return None
    candidates = [p for p in popular if len(p) >= MIN_LOOKALIKE_LENGTH and abs(len(p) - len(n)) <= 1]
    return next((p for p in sorted(candidates) if edit_distance(n, p) == 1), None)


def import_name_mixup(name: str, ecosystem: str) -> str | None:
    return IMPORT_NAME_MIXUPS.get(canonical(name, ecosystem)) if ecosystem == "pypi" else None
