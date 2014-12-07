Unity3DEncrypt
==============

Unity3DEncrypt<br>
<br>
These code is about encrypt data:<br>
CryptoPrefs.cs : It can save the data like Unit3d's PlayerPrefs. But it will encrypt the data when set , and also will decrypt the data when get . You do not need to care anything about encrypt or decrypt.<br>
<br>
XorFloat.cs : To Float . It will xor the value and a random key when set . And when it get vaule it will xor the same key to recover. So it will make the player not easy to change the value when they play.<br>
XorInt.cs : To Int . The same to up words.<br>
<br>
Cipher.cs : It can encrypt and decrypt the string by rsa public and private key . <br>
<br>
