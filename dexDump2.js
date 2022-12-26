var savepath = "/data/data/应用包名/";
var dexfile_dexfile_addr;
function FindArtAddr() {
    var symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
      //_ZN3art7DexFileC2EPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileE
        if (symbol.name.indexOf("DexFileC2") >= 0
            && symbol.name.indexOf("OatDexFileE") >= 0
        ) {
            console.log(JSON.stringify(symbol))
            dexfile_dexfile_addr = symbol.address
        }
    }
    hook_DexFile_DexFile()
}

function hook_DexFile_DexFile() {
    if (dexfile_dexfile_addr) {
        console.log("dexfile_dexfile_addr",dexfile_dexfile_addr)
        Interceptor.attach(dexfile_dexfile_addr, {
            onEnter: function (args) {
                this.base = ptr(args[1])
                this.size = parseInt(args[2], 16)
                //var size = ptr(parseInt(base,16) + 0x20).readInt() // 通过dex格式来计算出size
            }, onLeave: function (retval) {
                var name = "dexfile_dexfile_" + this.size + ".dex"
                var path = savepath + "/" + name
                var dex_file = new File(path, "wb")
                //Memory.protect(base,size,"rwx")
                dex_file.write(Memory.readByteArray(this.base, this.size))
                dex_file.flush();
                dex_file.close();
                console.log("dexfile::dexfile dump over path -> ", path)
            }
        })
    }
}
FindArtAddr()
