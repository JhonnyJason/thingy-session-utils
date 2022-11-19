import * as sess from "../output/index.js"
import { performance } from "perf_hooks"

const results = {}

const testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"

const count = 100

//############################################################
async function testAuthCode() {

    try {
        var request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        var request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        var kpHex = await sess.createKeyPairHex()
        var alicePrivHex = kpHex.secretKeyHex
        var alicePubHex = kpHex.publicKeyHex

        var context = "lenny@extensivlyon.coffee/mega-context"

        var seedHex = await sess.createSharedSecretHashHex(alicePrivHex, alicePubHex, context)
        var seedBytes = Buffer.from(seedHex, "hex")
        var authCodeHex = await sess.authCodeHex(seedHex, request1)
        var authCodeBytes = await sess.authCodeBytes(seedBytes, request1)
        if(authCodeHex != (Buffer.from(authCodeBytes)).toString("hex")) {
            throw new Error("Byte version and Hex version did not match!")
        }

        let success = true
        let hexMS = 0
        let bytesMS = 0
        let before = 0
        let after = 0
        let c = 0


        c = count
        before = performance.now()
        while(c--) {
            authCodeHex = sess.authCode(seedHex, request2)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            authCodeBytes = sess.authCodeBytes(seedHex, request2)
        }
        after = performance.now()
        bytesMS = after - before


        results.testAuthCode= {success, hexMS, bytesMS}

    } catch(error) {
        results.testAuthCode=error.message
    }

}

//############################################################
async function testSessionKey() {

    try {
        var request1 = {publicKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, nonce: 0, signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        var request2 = {authCode: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",timestamp: 0, data:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

        var kpHex = await sess.createKeyPairHex()
        var alicePrivHex = kpHex.secretKeyHex
        var alicePubHex = kpHex.publicKeyHex

        var context = "lenny@extensivlyon.coffee/mega-context"

        var seedHex = await sess.createSharedSecretHashHex(alicePrivHex, alicePubHex, context)
        var seedBytes = Buffer.from(seedHex, "hex")
        var sessionKeyHex = await sess.sessionKeyHex(seedHex, request1)
        var sessionKeyBytes = await sess.sessionKeyBytes(seedBytes, request1)
        if(sessionKeyHex != (Buffer.from(sessionKeyBytes)).toString("hex")) {
            throw new Error("Byte version and Hex version did not match!")
        }

        var testCipher = await sess.symmetricEncrypt(testString, sessionKeyHex)
        // var testUncipher = await sess.symmetricDecryptBytes(testCipher, sessionKeyBytes)
        var testUncipher = await sess.symmetricDecrypt(testCipher, sessionKeyHex)
        
        if(testUncipher != testString) {
            throw new Error("encyption and decryption of testString did not work with our sessionKey!")
        }

        let success = true
        let hexMS = 0
        let bytesMS = 0
        let before = 0
        let after = 0
        let c = 0


        c = count
        before = performance.now()
        while(c--) {
            sessionKeyHex = await sess.sessionKeyHex(seedHex, request2)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sessionKeyBytes = await sess.sessionKeyBytes(seedBytes, request2)
        }
        after = performance.now()
        bytesMS = after - before


        results.testSessionKey= {success, hexMS, bytesMS}

    } catch(error) {
        results.testSessionKey=error.message
    }

}

//############################################################
async function run() {

    await testAuthCode()
    await testSessionKey()

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

run()
