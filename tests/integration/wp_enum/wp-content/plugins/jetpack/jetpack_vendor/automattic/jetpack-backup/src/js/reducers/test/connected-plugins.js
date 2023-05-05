import connectedPlugins from '../connected-plugins';

describe( 'reducer', () => {
	describe( 'connectedPlugins', () => {
		test( 'should return the initial state when undefined state is passed', () => {
			expect( connectedPlugins( undefined, {} ) ).toEqual( {} );
		} );
	} );
} );
