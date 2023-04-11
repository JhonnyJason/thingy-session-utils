import * as sess from "../output/index.js"
import * as secUtl from "../output/node_modules/secret-manager-crypto-utils/index.js"
import { performance } from "perf_hooks"

const results = {}

const testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"

const count = 10000

//############################################################
async function testAuthCode() {

    try {
        var request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        var request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        var kpHex = await secUtl.createKeyPairHex()
        var alicePrivHex = kpHex.secretKeyHex
        var alicePubHex = kpHex.publicKeyHex

        var context = "lenny@extensivlyon.coffee/mega-context"

        var seedHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, alicePubHex, context)
        var seedBytes = Buffer.from(seedHex, "hex")
        
        var authCodeHex = await sess.createAuthCodeHex(seedHex, request1)
        var authCodeBytes = await sess.createAuthCodeBytes(seedBytes, request1)
        
        if(authCodeHex != (Buffer.from(authCodeBytes)).toString("hex")) {
            throw new Error("Byte version and Hex version did not match!")
        }

        var request1String = JSON.stringify(request1)
        var authCodeHexFromString = await sess.createAuthCodeHex(seedHex, request1String)
        if(authCodeHex != authCodeHexFromString) {
            throw new Error("Passing the same request as string did not give us the same authCode!")
        }
        

        let success = true
        let hexMS = 0
        let bytesMS = 0
        let requestStringHexMS = 0
        let requestStringBytesMS = 0
        let requestString = ""
        let before = 0
        let after = 0
        let c = 0


        c = count
        before = performance.now()
        while(c--) {
            authCodeHex = sess.createAuthCodeHex(seedHex, request2)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            authCodeBytes = sess.createAuthCodeBytes(seedHex, request2)
        }
        after = performance.now()
        bytesMS = after - before

        requestString = JSON.stringify(request2)

        c = count
        before = performance.now()
        while(c--) {
            authCodeHex = sess.createAuthCodeHex(seedHex, requestString)
        }
        after = performance.now()
        requestStringHexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            authCodeBytes = sess.createAuthCodeBytes(seedHex, requestString)
        }
        after = performance.now()
        requestStringBytesMS = after - before


        results.testAuthCode= {success, hexMS, bytesMS, requestStringHexMS, requestStringBytesMS}

    } catch(error) {
        results.testAuthCode=error.message
    }

}

//############################################################
async function testCreateSessionKey() {

    try {
        var request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        var request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        var kpHex = await secUtl.createKeyPairHex()
        var alicePrivHex = kpHex.secretKeyHex
        var alicePubHex = kpHex.publicKeyHex

        var context = "lenny@extensivlyon.coffee/mega-context"

        var seedHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, alicePubHex, context)
        var seedBytes = Buffer.from(seedHex, "hex")
        var sessionKeyHex = await sess.createSessionKeyHex(seedHex, request1)
        var sessionKeyBytes = await sess.createSessionKeyBytes(seedBytes, request1)
        if(sessionKeyHex != (Buffer.from(sessionKeyBytes)).toString("hex")) {
            throw new Error("Byte version and Hex version did not match!")
        }

        var request1String = JSON.stringify(request1)
        var sessionKeyHexFromString = await sess.createSessionKeyHex(seedHex, request1String)        
        if(sessionKeyHex != sessionKeyHexFromString) {
            throw new Error("Passing the same request as string did not give us the same sessionKey!")
        }

        var testCipher = await secUtl.symmetricEncrypt(testString, sessionKeyHex)
        // var testUncipher = await sess.symmetricDecryptBytes(testCipher, sessionKeyBytes)
        var testUncipher = await secUtl.symmetricDecrypt(testCipher, sessionKeyHex)
        
        if(testUncipher != testString) {
            throw new Error("encyption and decryption of testString did not work with our sessionKey!")
        }

        let success = true
        let hexMS = 0
        let bytesMS = 0
        let requestStringHexMS = 0
        let requestStringBytesMS = 0
        let requestString = ""
        let before = 0
        let after = 0
        let c = 0


        c = count
        before = performance.now()
        while(c--) {
            sessionKeyHex = await sess.createSessionKeyHex(seedHex, request2)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sessionKeyBytes = await sess.createSessionKeyBytes(seedBytes, request2)
        }
        after = performance.now()
        bytesMS = after - before


        requestString = JSON.stringify(request2)

        c = count
        before = performance.now()
        while(c--) {
            sessionKeyHex = await sess.createSessionKeyHex(seedHex, requestString)
        }
        after = performance.now()
        requestStringHexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sessionKeyBytes = await sess.createSessionKeyBytes(seedBytes, requestString)
        }
        after = performance.now()
        requestStringBytesMS = after - before



        results.testCreateSessionKey= {success, hexMS, bytesMS, requestStringHexMS, requestStringBytesMS}

    } catch(error) {
        results.testCreateSessionKey=error.message
    }

}

//############################################################
async function run() {

    await testAuthCode()
    await testCreateSessionKey()

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

run()
