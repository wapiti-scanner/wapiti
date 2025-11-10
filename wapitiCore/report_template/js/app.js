document.addEventListener('DOMContentLoaded', function() {
    const tabContainers = document.querySelectorAll('.tab-container');

    tabContainers.forEach(container => {
        const tabLinks = container.querySelectorAll('.tab-link');
        const tabContents = container.querySelectorAll('.tab-content');

        tabLinks.forEach(link => {
            link.addEventListener('click', function(event) {
                event.preventDefault();

                tabLinks.forEach(link => {
                    link.classList.remove('active');
                });

                this.classList.add('active');

                const targetId = this.getAttribute('href');

                tabContents.forEach(content => {
                    if ('#' + content.id === targetId) {
                        content.style.display = 'block';
                    } else {
                        content.style.display = 'none';
                    }
                });
            });
        });
    });
});