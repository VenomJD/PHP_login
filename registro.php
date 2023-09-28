<?php
include 'conexiondb.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("SELECT id FROM usuarios WHERE nombre_usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo "El nombre de usuario ya existe. Por favor, elige otro.";
        echo "<script>setTimeout(function(){window.history.back();}, 2000);</script>";
    } else {
        $stmt = $conn->prepare("INSERT INTO usuarios (nombre_usuario, contrasena) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $password);

        if ($stmt->execute()) {
            echo "Usuario registrado correctamente.";
            header("refresh:2; url=login.html");
        } else {
            echo "Error al registrar el usuario: " . $conn->error;
            echo "<script>setTimeout(function(){window.history.back();}, 2000);</script>";
        }
    }

    $stmt->close();
    $conn->close();
}
?>
