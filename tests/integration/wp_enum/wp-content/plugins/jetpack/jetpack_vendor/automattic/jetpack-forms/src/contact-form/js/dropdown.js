jQuery( function ( $ ) {
	$( document ).ready( function () {
		initializeSelectMenu();

		const observer = new MutationObserver( () => {
			initializeSelectMenu();
		} );

		observer.observe( document.querySelector( 'body' ), {
			childList: true,
			subtree: true,
		} );
	} );

	function initializeSelectMenu() {
		$( '.contact-form .contact-form-dropdown' ).selectmenu( {
			classes: {
				'ui-selectmenu-button': 'contact-form-dropdown__button',
				'ui-selectmenu-menu': 'contact-form-dropdown__menu',
			},
		} );
	}
} );
