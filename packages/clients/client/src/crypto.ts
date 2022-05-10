import * as encoding from "@walletconnect/encoding";
import cryptojs from "crypto-js";
import * as crypto from "@walletconnect/crypto";
import {
  IJsonRpcRequest,
  IJsonRpcResponseSuccess,
  IJsonRpcResponseError,
  IEncryptionPayload,
} from "@walletconnect/types";
import { convertArrayBufferToBuffer, convertBufferToArrayBuffer, convertBufferToHex, convertUtf8ToArrayBuffer } from "@walletconnect/utils";

export async function generateKey(length?: number): Promise<ArrayBuffer> {
  const _length = (length || 256) / 8;
  const bytes = crypto.randomBytes(_length);
  const result = convertBufferToArrayBuffer(encoding.arrayToBuffer(bytes));

  return result;
}

export async function verifyHmac(payload: IEncryptionPayload, key: Uint8Array): Promise<boolean> {
  // const cipherText = encoding.hexToArray(payload.data);
  // const iv = encoding.hexToArray(payload.iv);
  const hmac = encoding.hexToArray(payload.hmac);
  const hmacHex: string = encoding.arrayToHex(hmac, false);
  // const unsigned = encoding.concatArrays(cipherText, iv);
  
  // const chmac = await crypto.hmacSha256Sign(key, unsigned);
  // const chmacHex: string = encoding.arrayToHex(chmac, false);

  const keyHex = cryptojs.enc.Hex.parse(encoding.arrayToHex(key))
  const dataHex = cryptojs.enc.Hex.parse(payload.data)
  const ivHex = cryptojs.enc.Hex.parse(payload.iv)
  const chmacHex = cryptojs.HmacSHA256(dataHex.concat(ivHex), keyHex).toString(cryptojs.enc.Hex)


  if (encoding.removeHexPrefix(hmacHex) === encoding.removeHexPrefix(chmacHex)) {
    return true;
  }

  return false;
}

export async function encrypt(
  data: IJsonRpcRequest | IJsonRpcResponseSuccess | IJsonRpcResponseError,
  key: ArrayBuffer,
  providedIv?: ArrayBuffer,
): Promise<IEncryptionPayload> {
  await generateKey(128)
  const ivArrayBuffer: ArrayBuffer = providedIv || (await generateKey(128));
  const iv = encoding.bufferToHex(convertArrayBufferToBuffer(ivArrayBuffer));
  const contentString: string = JSON.stringify(data);

  const ivUtf8 = cryptojs.enc.Hex.parse( iv)
  const keyArry = encoding.bufferToHex(convertArrayBufferToBuffer(key));
  const key_Word = cryptojs.enc.Hex.parse(keyArry)
  const cipherText = cryptojs.AES.encrypt(contentString, key_Word, {iv: ivUtf8})
  const cipherTextHex = cryptojs.enc.Hex.stringify(cipherText.ciphertext)
  console.log(key_Word.toString(), ivUtf8.toString(), cipherText.toString(cryptojs.format.OpenSSL),  encoding.utf8ToHex(contentString))

  const hmac = cryptojs.HmacSHA256(cipherText.ciphertext.concat(ivUtf8), key_Word)
  const hmacHex = cryptojs.enc.Hex.stringify(hmac)

  return {
    data: cipherTextHex,
    hmac: hmacHex,
    iv: iv,
  };
}

export async function decrypt(
  payload: IEncryptionPayload,
  key: ArrayBuffer,
): Promise<IJsonRpcRequest | IJsonRpcResponseSuccess | IJsonRpcResponseError | null> {
  const _key = encoding.bufferToArray(convertArrayBufferToBuffer(key));

  if (!_key) {
    throw new Error("Missing key: required for decryption");
  }

  const verified: boolean = await verifyHmac(payload, _key);
  if (!verified) {
    return null;
  }
  const keyRaw = encoding.bufferToHex( convertArrayBufferToBuffer(key))
  const keyHex = cryptojs.enc.Hex.parse(keyRaw)
  const iv = cryptojs.enc.Hex.parse(payload.iv)
  const decrypted = cryptojs.AES.decrypt(payload.data, keyHex, {iv: iv, format: cryptojs.format.Hex})
  console.log("DECRYPTING", keyHex.toString(), iv.toString(), payload.data, )
  console.log("Result",   decrypted.toString(), decrypted)

  let data: IJsonRpcRequest;
  try {
    data = JSON.parse(decrypted.toString(cryptojs.enc.Utf8));
  } catch (error) {
    return null;
  }

  return data;
}
