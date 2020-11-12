const aesKey = createAesKey();
ah.proxy({
    // 请求发起前进入
    onRequest: function(config, handler) {
        var crypt = new JSEncrypt();
        var key = document.getElementById("key").value;
        crypt.setKey(key);
        var enc = aesEncrypt(config.body, aesKey);
        enc = enc.replace(/\+/g, '%2B');
        enc = enc.replace(/\=/g, '%3D');
        config.body = encodeURI(enc);
        config.headers['key'] = crypt.encrypt(aesKey);
        handler.next(config);
    },
    // 请求发生错误时进入，比如超时；注意，不包括http状态码错误，如404仍然会认为请求成功
    onError: function(err, handler) {
        handler.next(err)
    },
    // 请求成功后进入
    onResponse: function(response, handler) {
        var result = aesDecrypt(response.response, aesKey);
        response.response = result;
        handler.next(response)
    }
});
function createAesKey() {
    const expect = 16;
    var str = Math.random().toString(36).substr(2);
    while (str.length < expect) {
        str += Math.random().toString(36).substr(2)
    }
    str = str.substr(0, 16);
    return str
}
/**
 * AES 加密
 * @param word 待加密字段
 * @param keyStr 加密 key
 * @returns {string} 返回加密字段
 */
function aesEncrypt(word, keyStr) {
    keyStr = keyStr || aesKey;
    const key = CryptoJS.enc.Utf8.parse(keyStr);
    var srcs = '';
    switch (typeof (word)) {
        case 'string':
            srcs = CryptoJS.enc.Utf8.parse(word);
            break;
        case 'object':
            srcs = CryptoJS.enc.Utf8.parse(JSON.stringify(word));
            break;
        default:
            srcs = CryptoJS.enc.Utf8.parse(word.toString())
    }
    const encrypted = CryptoJS.AES.encrypt(srcs, key, {
        iv: key,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}
/**
 * AES 解密
 * @param word 待解密数据
 * @param keyStr 解密 key
 * @returns {string} 返回解密字符串
 */
function aesDecrypt(word, keyStr) {
    keyStr = keyStr || aesKey;
    const key = CryptoJS.enc.Utf8.parse(keyStr);
    const decrypt = CryptoJS.AES.decrypt(word, key, {
        iv: key,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return CryptoJS.enc.Utf8.stringify(decrypt).toString();
}