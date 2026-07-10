document.addEventListener('DOMContentLoaded', () => {
    console.log("[SYSTEM] Secure environment initialized.");
    
    const typewriters = document.querySelectorAll('.typewriter');
    
    typewriters.forEach(el => {
        const text = el.innerText;
        el.innerText = '';
        let i = 0;
        
        function type() {
            if (i < text.length) {
                el.innerHTML += text.charAt(i);
                i++;
                setTimeout(type, 60);
            }
        }
        setTimeout(type, 300);
    });
});