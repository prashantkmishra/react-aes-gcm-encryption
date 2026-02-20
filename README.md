# react-aes-gcm-encryption

AES-GCM encryption/decryption for React

## Installation

```sh
npm install react-aes-gcm-encryption
```

## Usage


```js
import { encrypt, decrypt } from 'react-aes-gcm-encryption';

// ...

const encrypted = await encrypt(
          text,
          key,
          keyLength,
          saltLength,
          ivLength,
          tagLength,
          iterations,
        );

const decrypted = await decrypt(
          text,
          key,
          keyLength,
          saltLength,
          ivLength,
          tagLength,
          iterations,
        );
     
```

## Example

https://prashantkmishra.github.io/react-aes-gcm-encryption/

## License

MIT

---

