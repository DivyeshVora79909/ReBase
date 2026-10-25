export class ConfigurationError extends TypeError {
  constructor(message, pathName) {
    super(pathName ? `${pathName}: ${message}` : message);
    this.name = 'ConfigurationError';
    this.path = pathName ?? null;
  }
}
