function byteToString(a)
{
    var buffer = Java.array('byte', a);
    var result = "";
    for(var i = 0; i < buffer.length; ++i){
        result += (String.fromCharCode(buffer[i] & 0xff));
    }
    return result;
}
function Bytetohex(arr) {
    var str = "";
    for (var i = 0; i < arr.length; i++) {
        var tmp = arr[i];
        if (tmp < 0) {
            tmp = (255 + tmp + 1).toString(16);
        } else {
            tmp = tmp.toString(16);
        }
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
}

function bytesToBase64(e) {
    var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4),
            r += '==';
            break
        }
        if (o = e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2),
            r += '=';
            break
        }
        t = e[a++],
        r += base64EncodeChars.charAt(h >> 2),
        r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
        r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
        r += base64EncodeChars.charAt(63 & t)
    }
    return r
}

function myPrintStack(){var Log=Java.use("android.util.Log");var Throwable=Java.use("java.lang.Throwable");send(Log.getStackTraceString(Throwable.$new()));}
function where(stack){var at = "\n";for (var i = 0; i < stack.length; i++){at += "堆栈信息("+i+"):"+stack[i].toString() + "\n";}return at;}
function myPrintStack1(){var thread=Java.use('java.lang.Thread');var instance=thread.$new();var stack=instance.currentThread().getStackTrace();var full_call_stack=where(stack);send(full_call_stack);}



Java.perform(function(){
Hash()
HmacHash()
crypto()

function Hash(){

var name ="";
var coinClass = Java.use("java.security.MessageDigest");
coinClass.getInstance.overload("java.lang.String").implementation=function(){

	name=arguments[0]
    send("[*] Algorithm type:"+name)
	return this.getInstance(name)
}
coinClass.update.overload("[B").implementation=function(v1){
	send("[*] Before encryption:"+byteToString(v1))

	return this.update(v1);
}
coinClass.digest.overload().implementation=function(){
	var v1 = this.digest();
	send("[*] After encryption:"+ Bytetohex(v1))
	send("============================================");
	return this.digest();
}

}
function HmacHash(){
	var name ="";
	var coinClass = Java.use("javax.crypto.Mac");
	var coinClassKey = Java.use("javax.crypto.spec.SecretKeySpec");
	coinClass.getInstance.overload("java.lang.String").implementation=function(){
	name=arguments[0]
	send("[*] Algorithm type:"+name)

	return this.getInstance(name)
}
	coinClassKey.$init.overload("[B","java.lang.String").implementation=function(){
	var v1 = arguments[0]
	var v2 = arguments[1]

	var value_hex = Bytetohex(v1);
	var value_base64 = bytesToBase64(v1)
	var vak = byteToString(v1)
	send("[*] KEY(PLAINTXT):"+vak)
   send("[*] Key(Hex):"+value_hex)
   send("[*] Key(Base64):"+value_base64)

	return this.$init(v1,v2)
}


	coinClass.doFinal.overload("[B").implementation=function(){
	var v1=arguments[0]
	send("[*] Before encryption:"+Bytetohex(v1))
	send("[*] After encryption:"+Bytetohex(this.doFinal(v1)))
	send("============================================");

	return this.doFinal(v1);
}

}
function crypto(){
	var name ="";
	var coinClassKey_encode = Java.use("java.security.spec.X509EncodedKeySpec");
	var coinClassKey_decode = Java.use("java.security.spec.PKCS8EncodedKeySpec");
	var coinClassiv = Java.use("javax.crypto.spec.IvParameterSpec");

	var Cipher = Java.use("javax.crypto.Cipher");
	Cipher.getInstance.overload("java.lang.String").implementation=function(){

	name=arguments[0]
	send("[*] Algorithm type:"+name)

	return this.getInstance(name)
}

	coinClassKey_encode.$init.overload("[B").implementation=function(){
 	var v1 = arguments[0]
 	var value_hex = Bytetohex(v1);
	 var value_base64 = bytesToBase64(v1)
	 var vak = byteToString(v1)
	 send("[*] KEY(PLAINTXT):"+vak)
    send("[*] Key(Hex):"+value_hex)
	send("[*] Key(Base64):"+value_base64)


 	return this.$init(v1)
}
	coinClassKey_decode.$init.overload("[B").implementation=function(){
 	var v1 = arguments[0]
 	var value_hex = Bytetohex(v1);
	 var value_base64 = bytesToBase64(v1)
	 var vak = byteToString(v1)
	 send("[*] KEY(PLAINTXT):"+vak)
	 send("[*] Key(Hex):"+value_hex)
	send("[*] Key(Base64):"+value_base64)

 	return this.$init(v1)
}
	coinClassiv.$init.overload("[B").implementation=function(){
 	var v1 = arguments[0]
 	var value_hex = Bytetohex(v1);
	 var value_base64 = bytesToBase64(v1)
	 var vak = byteToString(v1)
	 send("[*] IV(PLAINTXT):"+vak)
   	send("[*] IV(Hex):"+value_hex)
	send("[*] IV(Base64):"+value_base64)

 	return this.$init(v1)
}

	Cipher.doFinal.overload("[B").implementation=function(){
	var v1=arguments[0]
	var value_hex = Bytetohex(v1);
	var value_base64 = bytesToBase64(v1)
	var vak = byteToString(v1)
	send("[*] Before operation(PLAINTXT):"+vak)
	send("[*] Before operation(Hex):"+value_hex)
	send("[*] Before operation(Base64):"+value_base64)
	var value_hex = Bytetohex(this.doFinal(v1));
	var value_base64 = bytesToBase64(this.doFinal(v1))
	var vak = byteToString(this.doFinal(v1))
	send("[*] Before operation(PLAINTXT):"+vak)
	send("[*] After operation(Hex):"+value_hex)
	send("[*] After operation(Base64):"+value_base64)
	send("============================================");
	return this.doFinal(v1);
}

}


})
