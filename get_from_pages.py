import json, os


with open('full_out.txt','w') as fullout:
    for file in os.listdir('pages'):
        with open(f'pages/{file}', 'rb') as f:
            data = json.load(f)
            for signature in data['results']:
                fullout.write(signature['text_signature'] + '\t' + signature['hex_signature'] + '\n')
