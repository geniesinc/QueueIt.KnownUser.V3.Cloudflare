const {src, dest, series} = require("gulp");
const tsify = require("tsify");

const jsonModify = require('gulp-json-modify');
const vinylSource = require('vinyl-source-stream');
const browserify = require('browserify');
const babelify = require('babelify');
const tar = require('gulp-tar');
const gzip = require('gulp-gzip');

function bundle(){
	return browserify({
            basedir: ".",
            debug: false,
            entries: ["app.ts"],
            cache: {},
            packageCache: {},
        })
        .ignore("./miniflare.ts")
        .plugin(tsify)
        .transform(babelify, {
            global: true,              
            sourceMaps: true, 
            ignore: [/\/node_modules\/(?!yaml\/)/],  
            presets: ["es2015"]
        })
        .bundle()
        .pipe(vinylSource("queueitknownuser.bundle.js"))
        .pipe(dest("./dist"));
}

function makePackage() {
    return src([
        './dist/queueitknownuser.bundle.js',
    ])
        .pipe(tar('worker.tar'))
        .pipe(gzip())
        .pipe(dest('./dist'));
}

exports.stripPackage = () => {
    return src(['./package.json'])
        .pipe(jsonModify({ key: 'devDependencies', value: {}}))
        .pipe(jsonModify({ key: 'scripts', value: {}}))
        .pipe(dest('./'))
}

exports.buildArtifacts = series(bundle, makePackage);
exports.default = exports.buildArtifacts;
exports.bundle = bundle;