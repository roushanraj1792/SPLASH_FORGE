import os

import pytest
from dotenv import load_dotenv
from google import genai
from google.genai import errors

load_dotenv()


PROMPT = (
    "Reply with exactly: "
    "SentinelX Gemini connection successful."
)


def get_gemini_client():
    api_key = os.getenv("GEMINI_API_KEY")

    assert api_key, (
        "GEMINI_API_KEY is not configured"
    )

    return genai.Client(api_key=api_key)


def test_gemini_configuration():
    api_key = os.getenv("GEMINI_API_KEY")

    assert api_key, (
        "GEMINI_API_KEY is not configured"
    )


def test_gemini_connection():
    client = get_gemini_client()

    try:
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=PROMPT,
        )
    except errors.ClientError as error:
        if getattr(error, "code", None) == 429:
            pytest.skip(
                "Gemini API quota exhausted; "
                "connection test skipped."
            )
        raise

    assert response is not None
    assert response.text


def test_gemini_expected_response():
    client = get_gemini_client()

    try:
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=PROMPT,
        )
    except errors.ClientError as error:
        if getattr(error, "code", None) == 429:
            pytest.skip(
                "Gemini API quota exhausted; "
                "response test skipped."
            )
        raise

    assert response.text
    assert (
        "SentinelX Gemini connection successful."
        in response.text
    )
