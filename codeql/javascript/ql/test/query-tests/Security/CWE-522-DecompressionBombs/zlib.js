const fs = require("fs");
const zlib = require("node:zlib");
const { Readable } = require('stream');
const express = require('express');
const fileUpload = require("express-fileupload");
const app = express();
const port = 3000;
const stream = require('stream/promises');
app.use(fileUpload());
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});

app.post('/upload', async (req, res) => {
    zlibBombAsync(req.files.zipBombFile.data) // $ Source
    zlibBombAsyncSafe(req.files.zipBombFile.data);
    zlibBombSync(req.files.zipBombFile.data) // $ Source
    zlibBombSyncSafe(req.files.zipBombFile.data)
    zlibBombPipeStream(req.files.zipBombFile.data) // $ Source
    zlibBombPipeStreamSafe(req.files.zipBombFile.data)
    zlibBombPipeStreamPromises(req.files.zipBombFile.data).then(r => // $ Source
        console.log("sone"));
    res.send('Hello World!')
});


function zlibBombAsync(zipFile) {
    zlib.gunzip(
        zipFile.data, // $ Alert
        (err, buffer) => {
        });
    zlib.unzip(
        zipFile.data, // $ Alert
        (err, buffer) => {
        });

    zlib.brotliDecompress(
        zipFile.data, // $ Alert
        (err, buffer) => {
        });
}

function zlibBombAsyncSafe(zipFile) {
    zlib.gunzip(
        zipFile.data,
        { maxOutputLength: 1024 * 1024 * 5 },
        (err, buffer) => {
        });
    zlib.unzip(
        zipFile.data,
        { maxOutputLength: 1024 * 1024 * 5 },
        (err, buffer) => {
        });

    zlib.brotliDecompress(
        zipFile.data,
        { maxOutputLength: 1024 * 1024 * 5 },
        (err, buffer) => {
        });
}

function zlibBombSync(zipFile) {
    zlib.gunzipSync(zipFile.data, { finishFlush: zlib.constants.Z_SYNC_FLUSH }); // $ Alert
    zlib.unzipSync(zipFile.data); // $ Alert
    zlib.brotliDecompressSync(zipFile.data); // $ Alert
}

function zlibBombSyncSafe(zipFile) {
    zlib.gunzipSync(zipFile.data, { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: 1024 * 1024 * 5 });
    zlib.unzipSync(zipFile.data, { maxOutputLength: 1024 * 1024 * 5 });
    zlib.brotliDecompressSync(zipFile.data, { maxOutputLength: 1024 * 1024 * 5 });
}

function zlibBombPipeStream(zipFile) {
    const inputStream = Readable.from(zipFile.data);
    const outputFile = fs.createWriteStream('unzip.txt');
    inputStream.pipe(zlib.createGunzip()).pipe(outputFile); // $ Alert
    inputStream.pipe(zlib.createUnzip()).pipe(outputFile); // $ Alert
    inputStream.pipe(zlib.createBrotliDecompress()).pipe(outputFile); // $ Alert
}

async function zlibBombPipeStreamPromises(zipFile) {
    const inputStream = Readable.from(zipFile.data);
    const outputFile = fs.createWriteStream('unzip.txt');
    await stream.pipeline(
        inputStream,
        zlib.createGunzip(), // $ Alert
        outputFile
    )
}

function zlibBombPipeStreamSafe(zipFile) {
    const inputFile = Readable.from(zipFile.data);
    const outputFile = fs.createWriteStream('unzip.txt');
    inputFile.pipe(zlib.createGunzip({ maxOutputLength: 1024 * 1024 * 5 })).pipe(outputFile);
    inputFile.pipe(zlib.createUnzip({ maxOutputLength: 1024 * 1024 * 5 })).pipe(outputFile);
    inputFile.pipe(zlib.createBrotliDecompress({ maxOutputLength: 1024 * 1024 * 5 })).pipe(outputFile);
}
