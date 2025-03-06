def get_script(module):
    # Este script en Frida enumerará las clases cargadas (iOS ejemplo)
    return """
    Java.perform(function() {
    console.log("Enumerando métodos de una clase específica...");
    
    var className = """+module+"""; // Reemplaza con el nombre de la clase objetivo
    
    try {
        var targetClass = Java.use(className);
        var methods = targetClass.class.getDeclaredMethods();
        
        console.log("Métodos de la clase " + className + ":");
        methods.forEach(function(method) {
            console.log(method.toString());
          });
        } catch (error) {
            console.log("Error al acceder a la clase: " + error);
        }
    });

    """