def get_script():
    # Este script en Frida enumerará las clases cargadas (Android ejemplo)
    return """
    function bypassJavaFileCheck(){
        var UnixFileSystem = Java.use("java.io.UnixFileSystem")
        UnixFileSystem.checkAccess.implementation = function(file,access){

            var stack = stackTraceHere(false)

            const filename = file.getAbsolutePath();

            //console.log(filename);
            send({ action: 'log', message: moduleName });

            return this.checkAccess(file,access);
        }
    }

    function bypassNativeFileCheck(){
        var fopen = Module.findExportByName('libc.so','fopen')
        Interceptor.attach(fopen,{
            onEnter:function(args){
                this.inputPath = args[0].readUtf8String()
            },
            onLeave:function(retval){
                if(retval.toInt32() != 0){
                    //console.log(this.inputPath);
                    send({ action: 'log', message: this.inputPath });
                }
            }
        });

        var access = Module.findExportByName('libc.so','access')
        Interceptor.attach(access,{
            onEnter:function(args){
                this.inputPath = args[0].readUtf8String()
            },
            onLeave:function(retval){
                if(retval.toInt32()==0){
                        //console.log(this.inputPath);
                        send({ action: 'log', message: this.inputPath });
                    }
                }
        });
    }

    //bypassJavaFileCheck()
    bypassNativeFileCheck();
    """