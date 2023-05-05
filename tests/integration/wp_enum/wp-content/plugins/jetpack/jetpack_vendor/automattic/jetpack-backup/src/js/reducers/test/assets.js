import assets from '../assets';

describe( 'reducer', () => {
	describe( 'assets', () => {
		test( 'should return the initial state when undefined state is passed', () => {
			expect( assets( undefined, {} ) ).toEqual( {} );
		} );
	} );
} );
