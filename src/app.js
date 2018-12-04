import srpClient from 'secure-remote-password/client';
import srpServer from 'secure-remote-password/server';

window.localStorage.clear();

export const client = {
    sendRegistration: () => {
        const username = document.getElementById("reg-username").value;
        const password = document.getElementById("reg-password").value;
        const salt = srpClient.generateSalt();
        const privateKey = srpClient.derivePrivateKey(salt, username, password);
        const verifier = srpClient.deriveVerifier(privateKey);
        api.register(username, salt, verifier);
    },
    sendSignIn: () => {
        const username = document.getElementById("auth-username").value;
        const password = document.getElementById("auth-password").value;
        const clientEphemeral = srpClient.generateEphemeral();
        const signInResponse = api.requestSignIn(username, clientEphemeral.public);
        const privateKey = srpClient.derivePrivateKey(signInResponse.salt, username, password);
        try {
            const clientSession = srpClient.deriveSession(
                clientEphemeral.secret,
                signInResponse.serverEphemeralPublic,
                signInResponse.salt,
                username,
                privateKey
            );
            const validationResponse = api.validateSession(username, clientSession.proof, clientEphemeral.public);
            srpClient.verifySession(clientEphemeral.public, clientSession, validationResponse.proof);
            console.info("Verification successful");
        } catch (e) {
            console.error(e.message);
        }
    }
}

export const api = {
    register: (username, salt, verifier) => {
        const db = window.localStorage;
        db.setItem(username, JSON.stringify({salt, verifier}));
    },
    requestSignIn: (username, clientEphemeralPublic) => {
        const db = window.localStorage;
        const userRecord = db.getItem(username);
        if (!userRecord) {
            return api.bogusResponse();
        }
        const user = JSON.parse(userRecord);
        const serverEphemeral = srpServer.generateEphemeral(user.verifier);
        user.serverEphemeral = serverEphemeral;
        db.setItem(username, JSON.stringify(user));
        return {
            salt: user.salt,
            serverEphemeralPublic: serverEphemeral.public, 
        };
    },
    bogusResponse: () => {
        const username = "bogususername";
        const password = "boguspassword";
        const salt = srpClient.generateSalt();
        const privateKey = srpClient.derivePrivateKey(salt, username, password);
        const verifier = srpClient.deriveVerifier(privateKey);
        const serverEphemeralPublic = srpServer.generateEphemeral(verifier);
        return {
            salt,
            serverEphemeralPublic,
        };
    },
    validateSession: (username, clientSessionProof, clientEphemeralPublic) => {
        const db = window.localStorage;
        const userRecord = db.getItem(username);
        if (!userRecord) {
            console.error("Invalid request");
        }
        const user = JSON.parse(userRecord);
        const serverEphemeral = user.serverEphemeral;
        if (!serverEphemeral) {
            console.error("Invalid request");
        }
        try {
            const serverSession = srpServer.deriveSession(
                serverEphemeral.secret,
                clientEphemeralPublic,
                user.salt,
                username,
                user.verifier,
                clientSessionProof
            );
            return {
                proof: serverSession.proof,
            };
        } catch (e) {
            throw new Error(e.message);
        }
    }
}
