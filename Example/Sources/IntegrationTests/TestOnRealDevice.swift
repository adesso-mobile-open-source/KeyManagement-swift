//
//  TestOnRealDevice.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

#if targetEnvironment(simulator)
#error("Tests cannot be run on the simulator because it has no secure enclave.")
#endif
