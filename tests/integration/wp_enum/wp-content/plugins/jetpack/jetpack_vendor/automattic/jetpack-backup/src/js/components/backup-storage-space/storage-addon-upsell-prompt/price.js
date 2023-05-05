import { getCurrencyObject } from '@automattic/format-currency';

const Price = ( { fullPrice, discountedPrice, currency, hidePriceFraction } ) => {
	const finalPrice = discountedPrice > 0 ? discountedPrice : fullPrice;

	const { symbol, integer, fraction } = getCurrencyObject( finalPrice, currency );
	const showPriceFraction = hidePriceFraction === false || ! fraction.endsWith( '00' );
	return (
		<span>
			{ symbol }
			{ integer }
			{ showPriceFraction && fraction }
		</span>
	);
};

export default Price;
