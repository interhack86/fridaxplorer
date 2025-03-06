def get_script():
    # Este script en Frida enumerará las clases cargadas (iOS ejemplo)
    return """
    if (ObjC.available) {
        console.log("Enumerando clases cargadas...");

        var classes = ObjC.classes;
        for (var className in classes) {
            try {
                send({ action: 'log', message: 'Clase cargada: ' + className });
            } catch (error) {
                console.log("Error al imprimir clase: " + error);
            }
        }

        send("Enumeración completada.");
    } else {
        console.log("Objective-C no está disponible.");
    }
    """