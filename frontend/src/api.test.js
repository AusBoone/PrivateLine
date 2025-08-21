/**
 * Tests for the API helper module's runtime validation of base URLs.
 *
 * These tests focus on production-mode safeguards that prevent the application
 * from making requests to insecure (HTTP) backends which would expose
 * authentication cookies and other sensitive data.
 */

// ``describe`` and ``test`` are provided globally by Jest.

describe('api base URL security', () => {
  // Reset environment between tests to avoid cross-test contamination.
  afterEach(() => {
    jest.resetModules();
    delete process.env.REACT_APP_API_URL;
    process.env.NODE_ENV = 'test';
  });

  test(
    'throws when an insecure HTTP base URL is configured in production mode',
    () => {
      // Simulate a misconfiguration where a plaintext HTTP endpoint is used in
      // a production build.
      process.env.REACT_APP_API_URL = 'http://insecure.example.com';
      process.env.NODE_ENV = 'production';

      // Importing the module should immediately throw due to the protocol check.
      expect(() => {
        // eslint-disable-next-line global-require
        require('./api');
      }).toThrow(/HTTPS is required in production/);
    },
  );
});
