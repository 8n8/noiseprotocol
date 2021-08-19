#!/bin/bash

set -e

pytest
black tests
black noise
