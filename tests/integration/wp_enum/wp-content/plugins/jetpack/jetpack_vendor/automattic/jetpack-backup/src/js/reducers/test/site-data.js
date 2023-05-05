import siteData from '../site-data';

describe( 'reducer', () => {
	describe( 'siteData', () => {
		test( 'should return the initial state when undefined state is passed', () => {
			expect( siteData( undefined, {} ) ).toEqual( {} );
		} );
	} );
} );
