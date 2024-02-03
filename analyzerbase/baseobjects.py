from .common import *

class SetReprOrderedSet(OrderedSet):
    """OrderedSet that prints as a normal python set {x, y} instead of a OrderedSet([x, y]) when using repr()"""
    def __repr__(self):
        return "{" + f"{list(self)}"[1:-1] + "}"
    

    def __add__(self, other):
        self.union(other)
        return self
        


class SmartAttrObject(object):
    """
    Base class for objects that allow for smart attribute access. 
    The point of this is to provide a way to access common attributes of objects without having to write a bunch of boilerplate code.
    and to allow for common typos/abbreviations by AI. 
    Smart attribute access allows for the following:

    num_<attr> - Returns the number of items in the attribute
    min_<attr> - Returns the minimum value of the attribute
    max_<attr> - Returns the maximum value of the attribute
    uniq_<attr> - Returns the unique items in the attribute as SetReprOrderedSet
    most_common_<attr> - Returns the most common item in the attribute
    most_common_<n>_<attr> - Returns the n most common items in the attribute as a list of tuples (item, count)
    first_<attr> - Returns the first item in the attribute
    first<n>_<attr> - Returns the first n items in the attribute as a list
    last_<attr> - Returns the last item in the attribute
    last<n>_<attr> - Returns the last n items in the attribute as a list
    <attr>_counter - Returns a Counter object of the attribute

    Modifiers can be stacked. num_uniq_<attr> will return the number of unique items in the attribute.
    or uniq_<attr>_counter will return a Counter object of the unique items in the attribute.

    Smart attribute access also allows for common typos/abbreviations by AI such as dropped 's', removing '_all_'.
    """

    

    def __init__(self, uniq_fn=SetReprOrderedSet) -> None:
        super().__init__()
        self._smart_attr_access_enabled = True
        self._uniq_fn = uniq_fn # Can be SetReprOrderedSet or set


    def enable_smart_attr_access(self):
        """Enable smart attribute access"""
        self._smart_attr_access_enabled = True


    def disable_smart_attr_access(self):
        """Disable smart attribute access and return to normal attribute access for slighly better performance"""
        self._smart_attr_access_enabled = False

    def __getattr__(self, attr) -> Any:
        """Modifys value of attr before returning based <modifier>_addr while _smart_attr_access_enabled = True. See class docstring for more info"""
        # Return the attribute normally if smart attribute access is disabled
        if not super().__getattribute__('_smart_attr_access_enabled'):
            return super().__getattribute__(attr)

        modifier_fns = []
        if attr.startswith("num_"):
            modifier_fns.append(len)
            attr = attr.replace("num_", "")
        elif attr.startswith("min_"):
            modifier_fns.append(min)
            attr = attr.replace("min_", "")
        elif attr.startswith("max_"):
            modifier_fns.append(max)
            attr = attr.replace("max_", "")
        elif attr.endswith("_counter"):
            modifier_fns.append(Counter)
            attr = attr.replace("_counter", "")

        if attr.startswith("most_common"):
            n_str = attr.split("_")[1].replace("common", "")
            if n_str:
                n = int(n_str)
                modifier_fns.append(lambda x: Counter(x).most_common(n))
                attr = attr.replace(f"most_common{n_str}_", "")
            else:
                n = 1
                modifier_fns.append(lambda x: Counter(x).most_common(n)[0][0])
                attr = attr.replace("most_common_", "") + ("s" if not attr.endswith("s") else "")
        
        elif attr.startswith("first"):
            # Allow for first_<attr> and first<n>_<attr> to get the first n items
            end_slice = attr.split("_")[0].replace("first", "")
            if end_slice:
                modifier_fns.append(lambda x: x[:int(end_slice)])
                attr = attr.replace(f"first{end_slice}_", "")
            else:
                modifier_fns.append(lambda x: x[0] if x else None)
                attr = attr.replace("first_", "") + ("s" if not attr.endswith("s") else "")

        elif attr.startswith("last"):
            # Allow for last_<attr> and last<n>_<attr> to get the last n items
            start_slice = attr.split("_")[0].replace("last", "")
            if start_slice:
                modifier_fns.append(lambda x: x[-int(start_slice):])
                attr = attr.replace(f"last{start_slice}_", "")
            else:
                modifier_fns.append(lambda x: x[-1] if x else None)
                attr = attr.replace("last_", "") + ("s" if not attr.endswith("s") else "")

        if attr.endswith("_indexed"):
            modifier_fns.append(lambda x: dict(enumerate(x)))
            attr = attr.replace("_indexed", "")

        if attr.startswith("uniq_"):
            if modifier_fns:
                modifier_fns = [self._uniq_fn] + modifier_fns
            else:
                modifier_fns.append(self._uniq_fn) # SetReprOrderedSet or set
            attr = attr.replace("uniq_", "")


        # Hanndle common typos/abbreviations by AI
        _self_dir = dir(self)
        if not attr.startswith("all_") and "all_" + attr in _self_dir:
            attr = "all_" + attr
        elif not attr.endswith("s") and attr + "s" in _self_dir:
            attr += "s"
        elif attr.endswith("s") and attr[:-1] in _self_dir:
            attr = attr[:-1]

        # Return the modified attribute by calling the outfn on the infn of the attribute
        val = super().__getattribute__(attr)
        for fn in modifier_fns:
            val = fn(val)
        
        return val


class CachedProperty(property):
    """
    Descriptor for caching properties of CachedPropertyObjects
    """
    def __init__(self, func):
        self.func = func
        self.name = func.__name__

    
    def __get__(self, instance, owner) -> Any:
        """Return the cached value of the property if it exists, otherwise calculate it and cache it"""
        # Return self if accessed from class
        if instance is None:
            return self
        
        # Return cached value if the instance is frozen a the value exists in the cache
        if instance.is_frozen() and self.name in instance._cached_properties:
            return instance._cached_properties[self.name]
        
        # Calculate the value when its has not yet been cached or the instance is not frozen
        value = self.func(instance)

        # Store the calculated value if caching is enabled
        if instance.is_caching():
            instance._cached_properties[self.name] = value

        return value


def cachedproperty(func):
    """Decorator for caching properties of CachedPropertyObjects"""
    return CachedProperty(func)


class CachedPropertyObject:
    """
    Base class for objects that cache properties
    """

    def __init__(self) -> None:
        self._cached_properties = {}
        self._frozen = False
        self._caching = False


    def start_caching(self):
        """Start caching properties"""
        self._caching = True

    def stop_caching(self):
        """Stop caching properties"""
        self._caching = False

    def empty_cache(self):
        """Reset cached properties so subsequent calls to cached properties will recalculate them"""
        self._cached_properties.clear()

    def freeze(self):
        """
        Freeze cached properties so subsequent calls to cached properties will return the cached value
        instead of recalculating it
        """
        self._frozen = True

    def unfreeze(self):
        """Unfreeze cached properties so subsequent calls to cached properties will recalculate them"""
        self._frozen = False

    def is_frozen(self):
        """Return True if cached properties are frozen. Objects with frozen cached properties will not recalculate them"""
        return self._frozen
    
    def is_caching(self):
        """Return True if caching is enabled. Objects with caching disabled will not cache properties"""
        return self._caching


    @staticmethod
    def freeze_all(*args):
        """Freeze all CachedPropertyObjects in args"""
        for arg in args:
            if isinstance(arg, CachedPropertyObject):
                arg.freeze()
    
    @staticmethod
    def unfreeze_all(*args):
        """Unfreeze all CachedPropertyObjects in args"""
        for arg in args:
            if isinstance(arg, CachedPropertyObject):
                arg.unfreeze()

    @staticmethod
    def start_caching_all(*args):
        """Start caching all CachedPropertyObjects in args"""
        for arg in args:
            if isinstance(arg, CachedPropertyObject):
                arg.start_caching()
    
    @staticmethod
    def stop_caching_all(*args):
        """Stop caching all CachedPropertyObjects in args"""
        for arg in args:
            if isinstance(arg, CachedPropertyObject):
                arg.stop_caching()

    @staticmethod
    def empty_all(*args):
        """Empty all caches of CachedPropertyObjects in args"""
        for arg in args:
            if isinstance(arg, CachedPropertyObject):
                arg.empty_cache()    



class PostprocessableObject(object):
    """
    Base class for objects that can be exended dynamically by postprocessor objects
    """

    def __init__(self) -> None:
        self.postprocessor_objs = [] # List of postprocessor objects to extend the object with
        # Dict with list of postprocessor functions added to the object for each postprocessor object
        self.postprocessor_fn_names_by_class = defaultdict(list)

        # Tag to identify postprocessor functions for self in a postprocessor object
        self._postprocessor_fn_tag = f"_{self.__class__.__name__.lower()}_" 

    def add_postprocessor(self, postprocessor_obj):
        """Add a postprocessor object to the postprocessors list"""

        self._extend_self_with_postpostprocesor_fns(postprocessor_obj)
        
    def remove_postprocessor(self, postprocessor_obj):
        """Remove a postprocessor object from the postprocessors list"""
        self._remove_postprocessor_fn_from_self(postprocessor_obj)

    def remove_all_postprocessors(self):
        """Remove all postprocessor functions from self"""

        for postprocessor_obj in list(self.postprocessor_objs):
            self._remove_postprocessor_fn_from_self(postprocessor_obj)


    def _extend_self_with_postpostprocesor_fns(self, postprocessor_obj):
        """
        Add postprocessor functions from a postprocessor object to self
        Postprocessor functions are functions that take self as the first argument 
        and have the _postprocessor_fn_tag in their name.

        Abstact example: the _postprocessor_fn_tag for a subclass named 'Foo' is '_foo_'.
        So if a postprocessor object with the class name 'Bar' has a function named 'bar_foo_fn' 
        with a first argument of type 'Foo' then the function will be added to the 'Foo' object as 'bar_fn'.
        
        Bar._bar_foo_fn(bar_self, foo: Foo, *args) 
        -> foo.add_postprocessor(Bar()) 
        now foo.bar_fn(foo_self, *args) == Bar._bar_foo_fn(bar_self, foo_self, *args)
        
        Context Example:
        AttackDirReader.update_attack_log_paths(self, attack, *args, **kwargs) -> Attack.update_log_paths(self, *args, **kwargs)))
        """

        # Add the postprocessor object to the postprocessor_objs list
        self.postprocessor_objs.append(postprocessor_obj)
        postprocessor_class_name = postprocessor_obj.__class__.__name__

        # Iter over all attributes of the postprocessor object that are not already in self
        for attr in set(dir(postprocessor_obj)) - set(dir(self)):

            # Dont add private attributes or attributes that dont have the postprocessor tag for the instance Class
            if attr.startswith("_") or self._postprocessor_fn_tag not in attr:
                continue

            # Get the postprocessor function from the postprocessor object
            postprocesor_function = getattr(postprocessor_obj, attr)

            # Add the postprocessor function to self if it is a callable function 
            if callable(postprocesor_function):
                # New name is the original attribute name with the postprocessor tag replaced with an underscore
                fn_name = attr.replace(self._postprocessor_fn_tag, "_")
                # New function is a partial function with self as the first argument
                fn = partial(postprocesor_function, self)
                # Add the function to self
                setattr(self, fn_name, fn)
                # Add the function to the postprocessor_fn_names dict so it can be accessed by name or removed later
                self.postprocessor_fn_names_by_class[postprocessor_class_name].append(fn_name)

                print(f"Added {fn} {fn_name} to {self} from {postprocessor_obj}")


    def _remove_postprocessor_fn_from_self(self, postprocessor_obj):
        postprocessor_class_name = postprocessor_obj.__class__.__name__
        
        for fn_name in self.postprocessor_fn_names_by_class[postprocessor_class_name]:
            delattr(self, fn_name)

            print(f"Removed {fn_name} from {self}")

        self.postprocessor_objs.remove(postprocessor_obj)
        self.postprocessor_fn_names_by_class[postprocessor_class_name] = []
