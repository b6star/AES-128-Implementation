# AES-128 구현

AES의 암호화·복호화 과정을 직접 구현한 과제 코드입니다. 128비트 키와 128비트 블록을 사용하는 AES-128을 기준으로 하며, AES의 표준 연산을 바이트 단위로 처리합니다.

## 파일 구성

| 파일 | 설명 |
|---|---|
| `aes.py` | AES-128 암호화와 복호화의 전체 흐름을 담당합니다. `encrypt`, `decrypt` 함수와 PyCryptodome을 이용한 결과 비교 코드를 포함합니다. |
| `aes_tables.py` | AES S-box, 역 S-box, MixColumns 행렬, 역 MixColumns 행렬, 라운드 상수 `Rcon`을 정의합니다. |
| `round_key.py` | AES-128 키 스케줄을 구현합니다. 입력 키로부터 초기 키를 포함한 11개의 라운드 키를 생성합니다. |
| `state_box.py` | 128비트 블록을 4×4 상태 행렬로 변환하고, `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey` 및 각 역연산을 수행합니다. |

## AES-128 처리 순서

### 암호화

1. 입력 키로부터 11개의 라운드 키를 생성합니다.
2. 초기 `AddRoundKey`를 수행합니다.
3. 1~9라운드에서 다음 연산을 수행합니다.
   - `SubBytes`
   - `ShiftRows`
   - `MixColumns`
   - `AddRoundKey`
4. 10라운드에서는 `MixColumns`를 생략하고 나머지 연산을 수행합니다.

### 복호화

암호화의 역순으로 역 라운드 키를 사용하여 다음 연산을 수행합니다.

- `InvShiftRows`
- `InvSubBytes`
- `AddRoundKey`
- 1~9라운드에서 `InvMixColumns`

## 실행 방법

Python 3 환경에서 다음 명령을 실행합니다.

```bash
python aes.py
```

`aes.py`는 다음 과정을 수행합니다.

- 고정된 AES 키 `000102030405060708090a0b0c0d0e0f`를 사용합니다.
- 매 실행마다 `secrets.randbits(128)`으로 임의의 128비트 평문을 생성합니다.
- 직접 구현한 암호화 결과를 출력합니다.
- PyCryptodome의 AES-ECB 결과와 비교합니다.
- 직접 구현한 복호화 결과가 원래 평문과 같은지 확인합니다.

## 외부 라이브러리

`aes.py`의 `aes_reference` 함수는 구현 결과 검증을 위해 PyCryptodome을 사용합니다.

```bash
pip install pycryptodome
```

직접 구현한 `encrypt`와 `decrypt` 함수 자체는 `aes_tables.py`, `round_key.py`, `state_box.py`만으로 동작합니다.

## 함수 사용 예시

```python
from aes import encrypt, decrypt

key = 0x000102030405060708090a0b0c0d0e0f
plain_text = 0x00112233445566778899aabbccddeeff

cipher_text = encrypt(key, plain_text)
recovered_text = decrypt(key, cipher_text)

print(f"ciphertext: 0x{cipher_text:032x}")
print(f"plaintext : 0x{recovered_text:032x}")
```

키, 평문, 암호문은 각각 128비트 정수로 전달하며, 출력 시에는 32자리 16진수로 표현합니다. AES는 ECB 방식의 단일 블록 처리만 검증에 사용하며, 파일 암호화나 다중 블록 패딩은 포함하지 않습니다.
## AES State Matrix

AES는 128비트 블록을 열 우선 방식의 4×4 상태 행렬로 저장합니다.
입력 블록이 `000102030405060708090a0b0c0d0e0f`인 경우 상태 행렬은 다음과 같습니다.

```text
       col0 col1 col2 col3
row0    00   04   08   0c
row1    01   05   09   0d
row2    02   06   0a   0e
row3    03   07   0b   0f
```

구현에서는 행렬을 구성할 때 정수의 최하위 바이트부터 추출하므로,
바이트 추출은 오른쪽 아래 칸에서 시작합니다.
