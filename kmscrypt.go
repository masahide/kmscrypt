package kmscrypt

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/pkg/errors"
)

type data struct {
	Encrypted  []byte
	CryptedKey []byte
}

// AESEncrypt encryption with KMS and AES
func AESEncrypt(kmsSvc kmsiface.KMSAPI, keyID, keyName, plaintext string) (string, error) {
	res, err := kmsSvc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:             aws.String(keyID),
		KeySpec:           aws.String("AES_256"),
		EncryptionContext: map[string]*string{"keyName": &keyName},
	})
	if err != nil {
		return "", errors.Wrap(err, "kms.GenerateDataKey failed")
	}
	defer clearKey(res.Plaintext)

	block, err := aes.NewCipher(res.Plaintext)
	if err != nil {
		return "", errors.Wrap(err, "aes.NewCipher failed")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "ReadFull(rend.Reader,nonce) failed")
	}
	buf := &bytes.Buffer{}
	base64w := base64.NewEncoder(base64.StdEncoding, buf)
	zwriter, err := zlib.NewWriterLevel(base64w, zlib.BestCompression)
	if err != nil {
		return "", errors.Wrap(err, "zlib.NewWriterLevel failed")
	}
	err = gob.NewEncoder(zwriter).Encode(
		data{
			CryptedKey: res.CiphertextBlob,
			Encrypted:  aesgcm.Seal(nonce, nonce, []byte(plaintext), []byte(keyID)),
		},
	)
	zwriter.Close() // nolint errcheck
	base64w.Close() // nolint errcheck
	if err != nil {
		return "", errors.Wrap(err, "gob. encode failed")
	}
	return buf.String(), nil
}

// AESDecrypt decryption with KMS and AES
func AESDecrypt(kmsSvc kmsiface.KMSAPI, keyName, encoded string) (string, error) {
	zReader, err := zlib.NewReader(
		base64.NewDecoder(base64.StdEncoding,
			strings.NewReader(encoded),
		),
	)
	if err != nil {
		return "", errors.Wrap(err, "zlib.NewReader failed")
	}
	defer zReader.Close() // nolint errcheck
	cryptData := data{}
	if err = gob.NewDecoder(zReader).Decode(&cryptData); err != nil {
		return "", errors.Wrap(err, "gob decode failed")
	}

	input := &kms.DecryptInput{
		CiphertextBlob:    cryptData.CryptedKey,
		EncryptionContext: map[string]*string{"keyName": &keyName},
	}
	result, err := kmsSvc.Decrypt(input)
	if err != nil {
		return "", errors.Errorf("kms Decrypt failed. KEY:%s Dcrypt err:%s", keyName, err)
	}
	defer clearKey(result.Plaintext)
	block, err := aes.NewCipher(result.Plaintext)
	if err != nil {
		return "", errors.Wrap(err, "aes NewCipher failed")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce, ciphertext := cryptData.Encrypted[:aesgcm.NonceSize()], cryptData.Encrypted[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte(*result.KeyId))
	if err != nil {
		return "", errors.Wrap(err, "aesgcm.Open failed")
	}
	return string(plaintext), nil
}

func clearKey(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
