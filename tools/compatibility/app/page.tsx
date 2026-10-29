'use client';

import { motion } from 'motion/react';
import * as Dialog from '@radix-ui/react-dialog';

// Disposable integration fixture: no product behavior or learning data.
export default function Page() {
  return <main className="p-4">
    <motion.h1 initial={false}>互換性確認 / Compatibility probe</motion.h1>
    <Dialog.Root>
      <Dialog.Trigger>Open probe</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay />
        <Dialog.Content>
          <Dialog.Title>確認</Dialog.Title>
          <Dialog.Description>Local dependency fixture.</Dialog.Description>
          <Dialog.Close>Close</Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  </main>;
}
