function fetchData(url) {
    fetch(url, {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('access_token')
        }
    })
    .then(response => {
        if (response.status === 401) {
            // Manejar acceso no autorizado
            alert("Acceso no autorizado. Por favor, inicie sesión.");
        } else if (response.ok) {
            return response.json();
        }
    })
    .then(data => {
        console.log(data);
    });
}

// Usar esta función para acceder a múltiples recursos
fetchData('/resource1');
fetchData('/resource2');
fetchData('/resource3');
