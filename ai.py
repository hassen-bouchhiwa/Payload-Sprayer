from openai import OpenAI
import json


def ask_gpt(prompt, config_api_key):
    client = OpenAI(api_key=config_api_key)

    response = client.chat.completions.create(model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "You are an assistand for penetration tester and security analyst specializing in web application security"},
        {"role": "user", "content": prompt }
    ])

    return response.choices[0].message.content

def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(str(e))
        return {}

if __name__ == "__main__":
    import sys
    prompt = sys.argv[1]
    config = load_config()
    api_key = config['api_key']
    print(ask_gpt(prompt, api_key))