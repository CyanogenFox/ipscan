
start_btn.onclick = () =>{
    fetch('http://localhost:8080/sendips',{
        mode: 'no-cors',
        method: 'POST',
        headers:{
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "ip" : document.getElementById("address").value,
            "mask" : "/" + document.getElementById("mask").value,
            "thread_count": document.getElementById("threads").value
        })
    })
}