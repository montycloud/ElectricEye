from functools import wraps


class CheckRegister(object):
    checks = {}

    def register_check(self, service_name):
        """Decorator registers event handlers

        Args:
            event_type: A string that matches the event type the wrapped function
            will process.
        """

        def decorator_register(func):
            if service_name not in self.checks:
                self.checks[service_name] = {func.__name__: func}
            else:
                self.checks[service_name].update({func.__name__: func})

            @wraps(func)
            def func_wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return func_wrapper

        return decorator_register


def accumulate_paged_results(page_iterator, key):
    results = {key: []}
    for page in page_iterator:
        page_vals = page[key]
        results[key].extend(iter(page_vals))
    return results
