<?php
include 'conexiondb.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT contrasena FROM usuarios WHERE nombre_usuario = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($hashed_password);

    if ($stmt->fetch()) {
        if (password_verify($password, $hashed_password)) {
            echo "Inicio de sesión exitoso.";
            header("refresh:2; url=login.html");
        } else {
            echo "Contraseña incorrecta.";
            header("refresh:2; url=login.html");
        }
    } else {
        echo "Usuario no existe.";
        header("refresh:2; url=login.html");
    }

    $stmt->close();
    $conn->close();
}
?>
