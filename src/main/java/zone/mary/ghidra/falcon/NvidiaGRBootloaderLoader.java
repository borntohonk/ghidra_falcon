package zone.mary.ghidra.falcon;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class NvidiaGRBootloaderLoader extends BinaryLoader {
	private static final LanguageID FALCON4_LANGUAGE_ID = new LanguageID("falcon:LE:32:v4");
	private static final LanguageID FALCON5_LANGUAGE_ID = new LanguageID("falcon:LE:32:v5");

	@Override
	public String getName() {
		return "NVIDIA GR BootLoader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		long startOffset = reader.readUnsignedInt(0x0);
		long size = reader.readUnsignedInt(0x4);

		if (provider.length() - 0x10 < size) {
			return loadSpecs;
		}

		int checksum = 0;

		for (int i = 0; i < size / 4; i++) {
			checksum = (checksum + reader.readInt(startOffset + 0x10 + i * 4));
		}

		// TODO: Use the checksum to match against commonly known bootloaders

		loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(FALCON4_LANGUAGE_ID, new CompilerSpecID("default")), true));
		loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(FALCON5_LANGUAGE_ID, new CompilerSpecID("default")), true));

		return loadSpecs;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return Integer.MAX_VALUE;
	}

	@Override
	protected void loadProgramInto(Program program, Loader.ImporterSettings settings)
			throws IOException, CancelledException {
		ByteProvider provider = settings.provider();
		BinaryReader reader = new BinaryReader(provider, true);

		FlatProgramAPI api = new FlatProgramAPI(program);

		long startOffset = reader.readUnsignedInt(0x0);
		long size = reader.readUnsignedInt(0x4);
		long instructionMemoryOffset = reader.readUnsignedInt(0x8);
		long entrypointOffset = reader.readUnsignedInt(0xC);

		Address instructionMemoryAddress = api.toAddr(instructionMemoryOffset);
		Address entrypointAddress = api.toAddr(entrypointOffset);

		try {
			program.setImageBase(instructionMemoryAddress, true);
		} catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) {
			Msg.error(this, "Failed to set image base", e);
			return;
		}

		byte[] data = provider.readBytes(startOffset + 0x10, size);

		try {
			MemoryBlock block = api.createMemoryBlock("bootloader", instructionMemoryAddress, data, false);
			block.setPermissions(true, false, true);
		} catch (Exception e) {
			Msg.error(this, "Failed to load image", e);
			return;
		}

		api.addEntryPoint(entrypointAddress);
		api.disassemble(entrypointAddress);
		api.createFunction(entrypointAddress, "_bootloader_entrypoint");
	}
}
