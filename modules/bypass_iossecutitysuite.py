def get_script():
    # Este script en Frida bypasea la librearia IOSSecuritySuite
    return """
    const moduleName = "IOSSecuritySuite"; // Reemplaza con el nombre real del módulo
    const functionNamePattern = /^\$s16IOSSecuritySuite[A-Za-z0-9]+amI[A-Za-z0-9_]+$/; // Reemplaza con el patrón de función deseado

    const module = Process.findModuleByName(moduleName);
    if (module) {
      const exports = module.enumerateExports();

      for (const exp of exports) {
        if (functionNamePattern.test(exp.name)) {
          console.log("Función exportada encontrada:", exp.name);
          // Intercepta la función y muestra el valor de retorno
          Interceptor.attach(exp.address, {
            onLeave: function(retval) {
              if (retval == 0x01) {
                 console.log(`[!] Jailbreak detectado en la funciona ${exp.name}: ${retval}`);
                 retval.replace(0x00);
                 console.log(`[+] Cambiando valor de retorno para la función ${exp.name}: ${retval}`);
              }
            }
          });
        }
      }
    } else {
      console.log("Módulo no encontrado:", moduleName);
    }
    """
