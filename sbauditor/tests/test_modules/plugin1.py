# This file is part of SecurityBot.

# SecurityBot is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# SecurityBot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with SecurityBot.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

from check_register import CheckRegister

registry = CheckRegister()


@registry.register_check("test")
def plugin_func_1(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    finding = {"SchemaVersion": "2018-10-08", "Id": "test-finding"}
    yield finding
