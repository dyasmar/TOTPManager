function getCurrentSeconds() {
    return Math.round(new Date().getTime() / 1000.0);
}

function stripSpaces(str) {
    return str.replace(/\s/g, '');
}

function truncateTo(str, digits) {
    if (str.length <= digits) {
        return str;
    }
    return str.slice(-digits);
}

function encryptAndSave() {
    var passPhrase = document.getElementById("passPhraseID").value;

    var fileN = document.querySelector("#fileNameId").value;
    try {
        if (fileN == "" || fileN == null) throw 'Error: Did not supply a file name';
        if (passPhrase == "" || passPhrase == null) throw "No passphrase entered.";

        var tempTxt = "";
        for (var i = 0; i < data.length; i++) {
            cp = CryptoJS.AES.encrypt(data[i][1], passPhrase);
            ctivslt = getCtIvSlt(cp);

            tempTxt += data[i][0] + ","; // key name

            if (data[i][4] == "" && data[i][5] == "") {
                tempTxt += ctivslt[0] + ","; // encrypted key (previous iv and salt were not present...assuming its plain text)
            } else {
                tempTxt += data[i][1] + ","; // key that was previously encrypted (based on an iv and salt existing)
            }

            tempTxt += data[i][2] + ","; // digits
            tempTxt += data[i][3] + ","; // period
            if (data[i][4] == "" && data[i][5] == "") {
                tempTxt += ctivslt[1] + ","; // iv
                tempTxt += ctivslt[2]; // salt
            } else {
                tempTxt += data[i][4] + ","; // iv from previous encryption
                tempTxt += data[i][5]; // salt from previous encryption
            }

            if (i < data.length - 1) {
                tempTxt += "\r\n";
            }
        }

        var blob = new Blob([tempTxt]);
        fileN += ".txt";
        saveAs(blob, fileN);
        document.getElementById("saveID").disabled = true;
    } catch (err) {
        alert(err);
    }
}

function dispalyWarning(warn_str) {
    document.querySelector("#warningBoxID").style.visibility = 'visible';
    document.querySelector("#warningTextID").innerHTML = warn_str;
}

function hideWarning() {
    document.querySelector("#warningBoxID").style.visibility = 'hidden';
    document.querySelector("#warningTextID").innerHTML = "";
}

function updateProgress(per, timeLeft) {
    document.querySelector("#updatingClass").innerHTML = "Updating in " + timeLeft + " seconds";
    document.querySelector("#progressClass").max = per;
    document.querySelector("#progressClass").value = per - timeLeft;
}

function totp(secret_key) {
    return new OTPAuth.TOTP({
        algorithm: 'SHA1',
        digits: document.querySelector("#digitsID").value,
        period: document.querySelector("#periodID").value,
        secret: OTPAuth.Secret.fromB32(stripSpaces(secret_key))
    });
}

function checkIfSame() {
    var decryptSelect = document.getElementById("decryptSelectID").selectedIndex;
    var selectValue = document.getElementById("selectKey").selectedIndex;
    var secret_key_name = document.querySelector("#secretKeyNameID").value;
    var secret_key = document.querySelector("#secretKeyID").value;
    var digits = document.querySelector("#digitsID").value;
    var period = document.querySelector("#periodID").value;

    if (selectValue == 0) {
        return false;
    }
    if (secret_key_name !== data[selectValue][0]) {
        return true;
    }
    if (secret_key !== data[selectValue][1]) {
        return true;
    }
    if (digits !== data[selectValue][2]) {
        return true;
    }
    if (period !== data[selectValue][3]) {
        return true;
    }
    return false;
}

function checkIfNew() {
    var selectValue = document.getElementById("selectKey").selectedIndex;
    var secret_key_name = document.querySelector("#secretKeyNameID").value;
    var secret_key = document.querySelector("#secretKeyID").value;
    var digits = document.querySelector("#digitsID").value;
    var period = document.querySelector("#periodID").value;

    if (selectValue !== 0) {
        return false;
    }
    if ((secret_key_name !== null && secret_key_name !== "") &&
        (secret_key !== null && secret_key !== "") &&
        (digits !== null && digits !== "") &&
        (period !== null && period !== "")) {
        return true;
    }
    return false;
}

function update() {
    var passPhrase = document.getElementById("passPhraseID").value;
    var decryptSelect = document.getElementById("decryptSelectID").selectedIndex;
    var secret_key = document.querySelector("#secretKeyID").value;
    var digits = document.querySelector("#digitsID").value;
    var period = document.querySelector("#periodID").value;
    var selectIndx = document.querySelector("#selectKey").selectedIndex;
    var token = 0;
    if (secret_key && digits && period) {
        try {
            if (decryptSelect == 1) {
                if (passPhrase == "" || passPhrase == null) throw "No passphrase entered.";
                if (data[0] == null) throw "Have not encrypted this key previously, use plain text.";
                if (data[0][0] == "" || data[0][1] == "") throw "No IV or Salt stored. Encrypt and save and try again.";
                var cp = createCipherParams(secret_key, data[selectIndx][4], data[selectIndx][5]);
                secret_key = getMessage(cp, passPhrase);

                var cpTest = createCipherParams(data[0][1], data[0][4], data[0][5]);
                var testStr = getMessage(cpTest, passPhrase);
            }

            token = truncateTo(totp(secret_key).generate(), digits);
            document.querySelector("#tokenID").innerHTML = token;
            updateProgress(period, period - (getCurrentSeconds() % period));
            hideWarning();

            if (decryptSelect == 1) {
                if (testStr != "abcABC234765") {
                    dispalyWarning("Check your password");
                } else {
                    hideWarning();
                }
            }

        } catch (err) {
            if (err.message == null) {
                dispalyWarning("Error with the TOTP request or AES: " + err);
            } else {
                dispalyWarning("Error with the TOTP request or AES: " + err.message);
            }
        }
    }
    if (checkIfNew()) {
        document.getElementById("addKeyID").disabled = false;
    } else {
        document.getElementById("addKeyID").disabled = true;
    }
    if (checkIfSame()) {
        document.getElementById("updateKeyID").disabled = false;
    } else {
        document.getElementById("updateKeyID").disabled = true;
    }
    if (!checkIfSame() && (selectIndx != 0)) {
        document.getElementById("delKeyID").disabled = false;
    } else {
        document.getElementById("delKeyID").disabled = true;
    }
}

function updateList() {
    var decryptSelect = document.getElementById("decryptSelectID").selectedIndex;
    var selectValue = document.getElementById("selectKey").selectedIndex;
    var secret_key_name = document.querySelector("#secretKeyNameID").value;
    var secret_key = document.querySelector("#secretKeyID").value;
    var digits = document.querySelector("#digitsID").value;
    var period = document.querySelector("#periodID").value;

    data[selectValue][0] = secret_key_name;
    if (decryptSelect == 1) {
        data[selectValue][1] = secret_key;
    } else {
        data[selectValue][1] = secret_key;
    }
    data[selectValue][2] = digits;
    data[selectValue][3] = period;
    updateSelect();
    document.getElementById("selectKey").selectedIndex = selectValue;

    document.getElementById("saveID").disabled = false;
}

function addToList() {
    var tempRow = [];
    tempRow.push(document.querySelector("#secretKeyNameID").value);
    tempRow.push(document.querySelector("#secretKeyID").value);
    tempRow.push(document.querySelector("#digitsID").value);
    tempRow.push(document.querySelector("#periodID").value);
    tempRow.push("");
    tempRow.push("");

    if (data.length == 0) {
        var tempRowName = [];
        tempRowName.push("TestMe");
        tempRowName.push("abcABC234765");
        tempRowName.push("7");
        tempRowName.push("19");
        tempRowName.push("");
        tempRowName.push("");
        data.push(tempRowName);
    }
    data.push(tempRow);

    updateSelect();
    document.getElementById("selectKey").selectedIndex = data.length - 1;
    document.getElementById("saveID").disabled = false;
}

function deleteItem() {
    var selIdx = document.getElementById("selectKey").selectedIndex;
    data.splice(selIdx, 1);
    updateSelect();
    document.getElementById("selectKey").selectedIndex = 0;
    document.getElementById("saveID").disabled = false
}

function updateSelect() {
    var select = document.getElementById("selectKey");
    while (select.length > 1) {
        select.remove(1);
    }
    for (var i = 1; i < data.length; i++) {
        var opt = data[i][0];
        var el = document.createElement("option");
        el.textContent = opt;
        el.value = opt;
        select.appendChild(el);
    }
}

function FullReset() {
    resetSelect(true);
    document.querySelector("#fileNameID").textContent = "No file uploaded";
    document.querySelector("#file-input").value = null
    hideWarning();
    document.getElementById("saveID").disabled = true;
}

function resetSelect(allBool) {
    var select = document.getElementById("selectKey");
    select.selectedIndex = 0;
    //select.value = "---";
    document.querySelector("#passPhraseID").value = null;
    document.querySelector("#secretKeyNameID").value = null;
    document.querySelector("#secretKeyID").value = null;
    document.querySelector("#digitsID").value = null;
    document.querySelector("#periodID").value = null;
    document.querySelector("#tokenID").innerHTML = null;
    updateProgress(0, 0)
    if (allBool) {
        data = [];
        while (select.length > 1) {
            select.remove(1);
        }
    }
    hideWarning();
}

function createCipherParams(ct, iv, slt) {
    var cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(ct) });
    cipherParams.iv = CryptoJS.enc.Hex.parse(iv);
    cipherParams.salt = CryptoJS.enc.Hex.parse(slt);
    return cipherParams;
}

function getMessage(cipherParams, passPhrase) {
    var decrypted = CryptoJS.AES.decrypt(cipherParams, passPhrase);
    return decrypted.toString(CryptoJS.enc.Utf8);
}

function getCtIvSlt(cipherParams) {
    var tempArr = [];
    tempArr.push(cipherParams.ciphertext.toString(CryptoJS.enc.Base64));
    tempArr.push(cipherParams.iv.toString());
    tempArr.push(cipherParams.salt.toString());
    return tempArr;
}

document.querySelector("#selectKey").addEventListener('change', function() {
    if (this.selectedIndex == 0) {
        resetSelect(false);
    } else {
        document.querySelector("#secretKeyNameID").value = data[this.selectedIndex][0]
        document.querySelector("#secretKeyID").value = data[this.selectedIndex][1]
        document.querySelector("#digitsID").value = data[this.selectedIndex][2]
        document.querySelector("#periodID").value = data[this.selectedIndex][3]
    }
});

document.querySelector("#file-input").addEventListener('change', function() {
    // files that user has chosen
    var all_files = this.files;
    var fileNObj = document.querySelector("#fileNameID");

    if (all_files.length == 0) {
        resetSelect(false);
        //alert('Error : No file selected');
        return;
    }

    var file = all_files[0];
    document.querySelector("#fileNameID").textContent = file.name;

    // files types allowed
    var allowed_types = ['text/plain'];
    if (allowed_types.indexOf(file.type) == -1) {
        document.querySelector("#fileNameID").textContent = "No file uploaded";
        resetSelect(true);
        alert('Error : Incorrect file type');
        return;
    }

    var reader = new FileReader();

    // file reading started
    reader.addEventListener('loadstart', function() {});

    // file reading finished successfully
    reader.addEventListener('load', function(e) {
        resetSelect(true);

        // contents as text
        var text = e.target.result;
        // split by line breaks
        var rows = text.split("\r\n");

        for (var i = 0; i < rows.length; i++) {
            // split each row by comma
            var row_columns = rows[i].split(",");
            data.push(row_columns);
        }

        updateSelect();
    });

    // file reading failed
    reader.addEventListener('error', function() {
        resetSelect(true);
        document.querySelector("#fileNameID").textContent = "No file uploaded";
        alert('Error : Failed to read file');
    });

    // read as text file
    reader.readAsText(file);
});