/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.coff.relocation;

import ghidra.app.util.bin.format.coff.CoffFileHeader;
import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.CoffRelocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.NotFoundException;

public class WE32100_CoffRelocationHandler extends CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_WE_32100;
	}

	@Override
	public void relocate(Program program, Address address, Symbol symbol, CoffRelocation relocation)
			throws MemoryAccessException, NotFoundException {
		int addend = program.getMemory().getInt(address);

 		if (relocation.getType() == 0x0a) {
 			if (symbol.getName().equals(".text")) {
 				long sectionStart = address.getOffset() - relocation.getAddress();
 				program.getMemory().setInt(address, (int) (sectionStart + addend));
 			} else {
 				program.getMemory().setInt(address,
 						(int) symbol.getAddress().add(addend).getOffset());
 			}
		}
	}
}
