ENTRY(_start);

SECTIONS
{
    . = 0x0000;

    .text ALIGN(16) :
    {
        . = 0x0;
        *(.text.prologue)
        *(.text.implant)
        *(.text)
        *(.rodata*)
        *(.rdata*)

        _data_offset = .;
        
        *(.global*)
        *(.data*)
        
        *(.bss*)
        _got_offset = .;
        *(.got*)
        _epilogue_offset = .;
        *(.text.epilogue)        
    }

    /DISCARD/ :
    {
        *(.interp)
        *(.comment)
        *(.debug_frame)
        *(.pdata)
        *(.xdata)
        *(.reloc)
    }
}
