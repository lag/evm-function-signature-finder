import requests

def get_signatures(page: int):
    url = f"https://www.4byte.directory/api/v1/signatures/?format=json&page={page}"
    response = requests.get(url)
    with open(f"pages/signatures_{page}.json", "wb") as f:
        f.write(response.content)
    return response.json()

def main():
    page = 1
    while True:
        signatures = get_signatures(page)
        print('Downloaded page:',page)
        if 'next' in signatures and signatures['next'] is not None:
            page += 1
        else:
            print('Completed all downloads.')
            break

if __name__ == "__main__":
    main()

