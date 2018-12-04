module.exports = {
    entry: './src/app.js',
    output: {
        filename: './bundle.js',
        libraryTarget: 'var',
        library: 'app'
    },
}