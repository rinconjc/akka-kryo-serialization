package com.romix.akka.serialization.kryo

import akka.serialization.Serializer
import javax.crypto.{SecretKeyFactory, Cipher}
import java.security.{SecureRandom, Key}
import javax.crypto.spec.{SecretKeySpec, PBEKeySpec}
import akka.event.Logging

object Crypto {

  private def doCipher(keySpec: Key, input: Array[Byte], mode: Int) = {
    val cipher = Cipher.getInstance("AES")
    cipher.init(mode, keySpec)
    cipher.doFinal(input)
  }

  def encode(input: Array[Byte], pass: String) = {
    val salt = new SecureRandom().generateSeed(8)
    val key = generateKey(pass, salt)
    val ciphered = doCipher(key, input, Cipher.ENCRYPT_MODE)
    salt++ciphered
  }

  def decode(input:Array[Byte], pass:String)={
    val key = generateKey(pass, input.take(8))
    doCipher(key, input.drop(8), Cipher.DECRYPT_MODE)
  }

  private def generateKey(pass: String, salt: Array[Byte]) = {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    val spec = new PBEKeySpec(pass.toCharArray, salt, 1024, 128)
    val tmp = factory.generateSecret(spec)
    new SecretKeySpec(tmp.getEncoded, "AES")
  }

}

/**
 * 
 */
trait Encrypter extends Serializer{
  import Crypto._
  def secretKey:String

  abstract override def toBinary(o: AnyRef) = {
    printf("serialising and encrypting %s\n",o)
    //encode(super.toBinary(o), secretKey)
    super.toBinary(o)
  }

  abstract override def fromBinary(bytes: Array[Byte], manifest: Option[Class[_]]) = {
    printf("decrypting and deserialising bytes[%d]\n", bytes.size)
    //super.fromBinary(decode(bytes, secretKey), manifest)
    super.fromBinary(bytes,manifest)
  }

}

