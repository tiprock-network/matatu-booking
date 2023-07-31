var clock=document.getElementById('clock');

setInterval(function(){
    var date=new Date();
    var h=date.getHours();
    if(h>12){
        h=h-12;
        clock.innerHTML=
        h+":"+
        date.getMinutes()+":"+
        date.getSeconds()
    }
    else{
        clock.innerHTML=
        date.getHours()+":"+
        date.getMinutes()+":"+
        date.getSeconds()
    }
    
    
},1000);

