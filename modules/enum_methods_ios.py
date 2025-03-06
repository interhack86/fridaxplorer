def get_script(module):
    # Este script en Frida enumerará las clases cargadas (iOS ejemplo)
    return """
    const moduleName = '"""+module+"""'; // Reemplaza con el nombre real del módulo

    const module = Process.findModuleByName(moduleName);
    if (module) {
      const exports = module.enumerateExports();

      for (const exp of exports) {
          send({ action: 'log', message:'Función exportada encontrada:' + exp.name });
      };

    } else {
      send({ action: 'log', message:'Módulo no encontrado:' + moduleName });
    }
    """