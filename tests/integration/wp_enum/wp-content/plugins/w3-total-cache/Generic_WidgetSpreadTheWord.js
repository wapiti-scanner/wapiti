jQuery(function() {
	jQuery('.button-vote').on('click', function () {
        window.open('https://wordpress.org/support/plugin/w3-total-cache/reviews/#new-post');
    });

	jQuery('.button-share').on('click', function () {
        window.open('https://plus.google.com/share?url=' +
             encodeURIComponent(w3tc_spread_the_word_product_url), '_blank');
    });

	jQuery('.button-tweet').on('click', function () {
        window.open('https://twitter.com/?status=' +
            encodeURIComponent(w3tc_spread_the_word_tweet), '_blank');
    });

	jQuery('.button-like').on('click', function () {
        window.open('https://www.facebook.com/sharer.php?u=' +
            encodeURIComponent(w3tc_spread_the_word_product_url), '_blank');
    });

	jQuery('.button-rating').on('click', function () {
        window.open(w3tc_spread_the_word_rate_url, '_blank');
    });
});
